"""iiser-login against a fake campus portal and a fake connectivity check (no campus network needed)."""

from __future__ import annotations

import datetime as dt
import socket
import struct
import sys
import threading
import time
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
    return lambda: said.read_text().replace('"', "").splitlines() if said.exists() else []  # cmd's echo keeps quotes


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


# ------------------------------------------------------------------ a fixed session length (campus Wi-Fi)
def _forced_sign_ins(ago: list[float], link: str = "") -> None:
    """Log lines for sign-ins the page forced, this many seconds ago."""
    il.STATE.mkdir(parents=True, exist_ok=True)
    with open(il.STATE / "log.txt", "a", encoding="utf-8") as f:
        for s in ago:
            f.write(
                f"{dt.datetime.fromtimestamp(time.time() - s):%Y-%m-%d %H:%M:%S} {link + ': ' if link else ''}signed in\n"
            )
        f.write(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} keeping the campus network signed in\n")


def test_session_limit_is_learned_from_the_log(fake):
    _forced_sign_ins([3 * 1740 + 100, 2 * 1740 + 100, 1740 + 100, 100])
    _forced_sign_ins([5000, 3000, 100], link="wlan0")  # gaps of 2000 s and 2900 s: no fixed length
    limits = il.session_limits()
    assert abs(limits[""][1] - (1740 - 60)) <= 1 and abs(limits[""][0] - (time.time() - 100)) <= 2
    assert limits["wlan0"][1] is None


def test_signs_in_again_ahead_of_a_fixed_limit(fake, monkeypatch):
    kc = il.Keychain()
    kc.save("student", "s3cret pa$$")
    _forced_sign_ins([1600 + 2 * 1740, 1600 + 1740, 1600])  # ended every 29 min; this session began 1600 s ago
    fake.signed_in = True
    naps = []

    def nap(s):
        naps.append(s)
        if len(naps) == 2:
            fake.signed_in = False  # this network ends it on the old clock all the same

    monkeypatch.setattr(il.time, "sleep", nap)
    il.keep(kc, rounds=3)
    log = (il.STATE / "log.txt").read_text()
    assert "signed in again, ahead of the 28-minute limit" in log and "s3cret" not in log
    assert naps[0] == 3  # close to the end it looks every few seconds
    assert "doesn't extend the session here" in log and log.rstrip().endswith(" signed in") and fake.signed_in


def test_off_campus_it_does_not_sign_in_ahead(fake, monkeypatch):
    kc = il.Keychain()
    kc.save("student", "s3cret pa$$")
    _forced_sign_ins([1600 + 2 * 1740, 1600 + 1740, 1600])
    fake.signed_in = True  # online, but the portal isn't there
    monkeypatch.setattr(il, "PORTAL", "http://127.0.0.1:1")
    monkeypatch.setattr(il.time, "sleep", lambda s: None)
    il.keep(kc, rounds=2)
    assert "couldn't reach" not in (il.STATE / "log.txt").read_text() and fake.calls == []


# ----------------------------------------------------------------- each campus link itself (Linux only)
class FakeDNS:
    """Answers the firewall's name with 127.0.0.1 (after a CNAME, as some resolvers do), anything else NXDOMAIN."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port, self.asked = self.sock.getsockname()[1], []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                q, peer = self.sock.recvfrom(2048)
            except OSError:
                return
            i, labels = 12, []
            while q[i]:
                labels.append(q[i + 1 : i + 1 + q[i]].decode())
                i += q[i] + 1
            name, question = ".".join(labels), q[12 : i + 5]
            self.asked.append(name)
            if name == il.HOST:
                target = b"\x06portal\x07example\x00"
                answers = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target
                answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
                head = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 2, 0, 0)
            else:
                answers, head = b"", q[:2] + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0)
            self.sock.sendto(head + question + answers, peer)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="SO_BINDTODEVICE is Linux's")
def test_signs_in_through_a_chosen_interface(fake, monkeypatch, capsys):
    dns = FakeDNS()
    monkeypatch.setattr(il, "DNS_PORT", dns.port)
    monkeypatch.setattr(il, "link_dns", lambda iface: ["127.0.0.1"])
    monkeypatch.setattr(il, "_dns_cache", {})
    port = urllib.parse.urlsplit(fake.base).port
    monkeypatch.setattr(il, "PORTAL", f"http://{il.HOST}:{port}")  # reached at the address the link's own DNS gives
    s = il.bound("lo")
    assert s.getsockopt(socket.SOL_SOCKET, il.SO_BINDTODEVICE, 16).rstrip(b"\0") == b"lo"
    s.close()
    assert "Not an interface name" in il.interfaces(["eth0;", "x"])
    assert il.main(["interfaces", "lo"]) == 0 and "On:" in capsys.readouterr().out and il.bind_to() == ["lo"]
    kc = il.Keychain()
    kc.save("student", "s3cret pa$$")
    assert il.main([]) == 0 and fake.signed_in and il.HOST in dns.asked
    assert "lo: signed in" in (il.STATE / "log.txt").read_text()
    il.keep(kc, once=True)
    assert ("live", "192") in fake.calls
    il.main(["status"])
    assert "lo: campus, online (firewall 127.0.0.1)" in capsys.readouterr().out
    assert il.dns_a("elsewhere.example", "127.0.0.1", "lo") is None  # its DNS doesn't know it: not a campus link
    assert il.main(["logout"]) == 0 and not fake.signed_in
    assert il.main(["interfaces", "off"]) == 0 and il.bind_to() is None
