"""iiser-login against a fake campus portal and a fake connectivity check (no campus network needed)."""

from __future__ import annotations

import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "src"))
import iiser_login as il  # noqa: E402


class Fake:
    def __init__(self):
        self.signed_in = False
        self.calls = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", headers=()):
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/generate_204":
                    if fake.signed_in:
                        return self._send(204)
                    return self._send(302, b"", [("Location", f"https://{il.HOST}:8090/httpclient.html")])
                if self.path.startswith("/live"):
                    q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    fake.calls.append(("live", q["mode"][0]))
                    ack = "ack" if fake.signed_in else "login_again"
                    return self._send(
                        200,
                        f"<?xml version='1.0'?><requestresponse><ack><![CDATA[{ack}]]></ack></requestresponse>".encode(),
                    )
                return self._send(404)

            def do_POST(self):
                form = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
                fake.calls.append((self.path, form.get("mode", [""])[0]))
                if self.path == "/login.xml":
                    ok = form.get("username") == ["student"] and form.get("password") == ["s3cret pa$$"]
                    fake.signed_in = ok
                    status, msg = ("LIVE", "You are signed in as {username}") if ok else ("LOGIN", "Login failed")
                    body = f"<requestresponse><status><![CDATA[{status}]]></status><message><![CDATA[{msg}]]></message></requestresponse>"
                    return self._send(200, body.encode())
                if self.path == "/logout.xml":
                    fake.signed_in = False
                    return self._send(
                        200, b"<requestresponse><message><![CDATA[You've signed out]]></message></requestresponse>"
                    )
                return self._send(404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def fake(tmp_path, monkeypatch):
    f = Fake()
    monkeypatch.setattr(il, "PORTAL", f.base)
    monkeypatch.setattr(il, "PROBE", f.base + "/generate_204")
    monkeypatch.setattr(il, "CONFIG", tmp_path / "config")
    monkeypatch.setattr(il, "STATE", tmp_path / "state")
    monkeypatch.setattr(il, "SERVICE", "iiser-sophos-login-test")
    if sys.platform.startswith("linux"):  # don't touch a real keyring on a developer's machine
        monkeypatch.setattr(il.shutil, "which", lambda name: None)
    yield f
    f.server.shutdown()
    il.Keychain().forget()


def test_portal_is_detected_and_signed_in(fake):
    kc = il.Keychain()
    assert il.probe() == "portal"
    assert il.sign_in(kc) is False  # nothing saved yet
    kc.save("student", "s3cret pa$$")
    assert kc.username() == "student" and kc.password() == "s3cret pa$$"
    assert il.sign_in(kc) is True
    assert il.probe() == "online"
    log = (il.STATE / "log.txt").read_text()
    assert "signed in" in log and "s3cret" not in log


def test_wrong_password_is_refused(fake):
    kc = il.Keychain()
    kc.save("student", "wrong")
    assert il.sign_in(kc) is False
    assert "sign-in refused: Login failed" in (il.STATE / "log.txt").read_text()


def test_keep_signs_in_then_keeps_alive(fake):
    kc = il.Keychain()
    kc.save("student", "s3cret pa$$")
    il.keep(kc, once=True)
    assert fake.signed_in and ("/login.xml", "191") in fake.calls
    il.keep(kc, once=True)  # online now: a keep-alive (the first one is due at once in a new run)
    assert ("live", "192") in fake.calls


def test_logout_and_cli(fake, capsys):
    kc = il.Keychain()
    kc.save("student", "s3cret pa$$")
    assert il.main([]) == 0
    assert fake.signed_in
    assert il.main(["logout"]) == 0 and not fake.signed_in
    assert "signed out" in capsys.readouterr().out
    assert il.main(["status"]) == 0
    assert "credentials: saved for student" in capsys.readouterr().out
    assert il.main(["forget"]) == 0 and il.Keychain().username() is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the file fallback is the Linux-without-keyring path")
def test_password_file_is_private(fake):
    import stat

    il.Keychain().save("student", "x")
    mode = stat.S_IMODE((il.CONFIG / "password").stat().st_mode)
    assert mode == 0o600


def test_setup_for_other_programs(fake, monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cret pa$$\n"))
    assert il.main(["setup", "--username", "student", "--password-stdin"]) == 0
    assert il.Keychain().password() == "s3cret pa$$" and fake.signed_in
    assert "s3cret" not in capsys.readouterr().out


@pytest.fixture
def kurooto(fake, tmp_path, monkeypatch):
    """A stand-in `kurooto` command that writes down what it was asked to say."""
    said = tmp_path / "said.txt"
    if sys.platform == "win32":
        exe = tmp_path / "kurooto.cmd"
        exe.write_text(f'@echo %* >> "{said}"\r\n')
    else:
        exe = tmp_path / "kurooto"
        exe.write_text(f'#!/bin/sh\necho "$@" >> "{said}"\n')
        exe.chmod(0o755)
    which = il.shutil.which
    monkeypatch.setattr(
        il.shutil, "which", lambda name, *a, **k: str(exe) if name.startswith("kurooto") else which(name, *a, **k)
    )
    return lambda: said.read_text().splitlines() if said.exists() else []


def test_kurooto_needs_kurooto(fake, capsys):
    assert il.main(["kurooto", "on"]) == 0
    assert "isn't installed" in capsys.readouterr().out and il.kurooto("status") == "off"
    assert il.tell("hi", key="x") is False


def test_problems_reach_you_through_kurooto(kurooto, capsys):
    kc = il.Keychain()
    kc.save("student", "wrong")
    assert il.sign_in(kc) is False and kurooto() == []  # off: nothing sent
    assert il.main(["kurooto", "on"]) == 0 and il.kurooto("status") == "on"
    assert "--title Campus login" in kurooto()[0] and "will tell you" in kurooto()[0]
    assert il.sign_in(kc) is False and il.sign_in(kc) is False
    told = kurooto()
    assert len(told) == 2 and "refused the sign-in (Login failed)" in told[1]  # the second refusal: not repeated
    assert "wrong" not in "".join(told)
    il.main(["status"])
    assert "kurooto: on" in capsys.readouterr().out
    assert il.main(["kurooto", "off"]) == 0 and il.kurooto("status") == "off"
