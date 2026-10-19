"""iiser-login: keep your computer signed in to IISER Pune's network login (the Sophos page at
firewall.iiserpune.ac.in:8090), so the internet keeps working on campus Wi-Fi and ethernet without opening the page.

    iiser-login setup            save your campus username and password (in your system's keychain)
                                 (--username NAME --password-stdin: the same, for other programs)
    iiser-login                  sign in now, if the campus page is asking
    iiser-login keep             stay signed in: checks every minute, signs in when the page intercepts, and sends the
                                 page's keep-alive every 3 minutes (what `autostart on` runs in the background)
    iiser-login status           are you on campus, signed in, and are credentials saved
    iiser-login logout           sign out
    iiser-login autostart on|off|status    run `keep` whenever you sign in to this computer
    iiser-login forget           delete the saved credentials
    iiser-login kurooto on|off|status    tell you about sign-in problems through Kurooto (Telegram), if you use it

Works on Windows, macOS and Linux with only Python's standard library. The password goes only to the campus portal
(over HTTPS, certificate checked) and is never written to logs. Not affiliated with IISER Pune.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import getpass
import http.client
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

__version__ = "0.1.0"
HOST, PORT = "firewall.iiserpune.ac.in", 8090
PORTAL = os.environ.get("IISER_LOGIN_PORTAL", f"https://{HOST}:{PORT}")  # tests point this at a fake
PROBE = os.environ.get("IISER_LOGIN_PROBE", "http://connectivitycheck.gstatic.com/generate_204")
SERVICE = "iiser-sophos-login"
LIVE_EVERY = 180  # the portal's own page sends a keep-alive every 180 s


def home_dir(kind: str) -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / SERVICE
        return base / kind
    if sys.platform == "darwin":
        return Path.home() / "Library" / ("Logs" if kind == "state" else "Application Support") / SERVICE
    xdg = {"config": ("XDG_CONFIG_HOME", ".config"), "state": ("XDG_STATE_HOME", ".local/state")}[kind]
    return Path(os.environ.get(xdg[0]) or Path.home() / xdg[1]) / SERVICE


CONFIG, STATE = home_dir("config"), home_dir("state")


def log(msg: str) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    line = f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
    print(line, flush=True)
    with open(STATE / "log.txt", "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ------------------------------------------------------------------------------------------- keychain
class Keychain:
    """The password in the system's keychain; the username (not secret) in a small file next to it."""

    def __init__(self):
        self.user_file = CONFIG / "username"
        self.fallback = CONFIG / "password"

    def username(self) -> str | None:
        try:
            return self.user_file.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def save(self, user: str, password: str) -> str:
        CONFIG.mkdir(parents=True, exist_ok=True)
        self.user_file.write_text(user + "\n", encoding="utf-8")
        where = self._store(user, password)
        if where != "file":
            self.fallback.unlink(missing_ok=True)
        return where

    def password(self) -> str | None:
        user = self.username()
        if not user:
            return None
        pw = self._load(user)
        if pw is None and self.fallback.exists():
            pw = self.fallback.read_text(encoding="utf-8").rstrip("\n")
        return pw

    def forget(self) -> None:
        user = self.username()
        if user:
            self._delete(user)
        self.fallback.unlink(missing_ok=True)
        self.user_file.unlink(missing_ok=True)

    # each system's own store
    def _store(self, user: str, password: str) -> str:
        if sys.platform == "win32":
            _win_cred_write(user, password)
            return "Windows Credential Manager"
        if sys.platform == "darwin":
            r = subprocess.run(
                ["security", "add-generic-password", "-U", "-a", user, "-s", SERVICE, "-w", password],
                capture_output=True,
            )
            if r.returncode == 0:
                return "macOS Keychain"
        elif shutil.which("secret-tool"):
            r = subprocess.run(
                ["secret-tool", "store", "--label", "IISER network login", "service", SERVICE, "username", user],
                input=password.encode(),
                capture_output=True,
            )
            if r.returncode == 0:
                return "your keyring (Secret Service)"
        self.fallback.write_text(password + "\n", encoding="utf-8")
        os.chmod(self.fallback, 0o600)
        return "file"

    def _load(self, user: str) -> str | None:
        if sys.platform == "win32":
            return _win_cred_read()
        if sys.platform == "darwin":
            r = subprocess.run(
                ["security", "find-generic-password", "-a", user, "-s", SERVICE, "-w"], capture_output=True, text=True
            )
            return r.stdout.rstrip("\n") if r.returncode == 0 else None
        if shutil.which("secret-tool"):
            r = subprocess.run(
                ["secret-tool", "lookup", "service", SERVICE, "username", user], capture_output=True, text=True
            )
            return r.stdout if r.returncode == 0 and r.stdout else None
        return None

    def _delete(self, user: str) -> None:
        if sys.platform == "win32":
            ctypes.windll.advapi32.CredDeleteW(SERVICE, 1, 0)
        elif sys.platform == "darwin":
            subprocess.run(["security", "delete-generic-password", "-a", user, "-s", SERVICE], capture_output=True)
        elif shutil.which("secret-tool"):
            subprocess.run(["secret-tool", "clear", "service", SERVICE, "username", user], capture_output=True)


if sys.platform == "win32":
    from ctypes import wintypes

    class _CRED(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]


def _win_cred_write(user: str, password: str) -> None:
    blob = password.encode("utf-16-le")
    buf = (ctypes.c_byte * len(blob)).from_buffer_copy(blob)
    c = _CRED(Type=1, TargetName=SERVICE, CredentialBlobSize=len(blob), CredentialBlob=buf, Persist=2, UserName=user)
    if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(c), 0):
        raise OSError("Windows refused to save the credential")


def _win_cred_read() -> str | None:
    p = ctypes.POINTER(_CRED)()
    if not ctypes.windll.advapi32.CredReadW(SERVICE, 1, 0, ctypes.byref(p)):
        return None
    try:
        c = p.contents
        return ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le")
    finally:
        ctypes.windll.advapi32.CredFree(p)


# --------------------------------------------------------------------------------------------- kurooto
# Kurooto (github.com/avtarfr/kurooto) is a personal assistant on your computer; `kurooto notify` reaches you on
# Telegram. With `iiser-login kurooto on`, sign-in problems are sent that way, at most once every 6 hours per problem.
KUROOTO_FILE = "kurooto.json"


def kurooto_cmd() -> str | None:
    """The saved `kurooto` command (absolute, so it works from a background service), if the integration is on."""
    try:
        import json

        cfg = json.loads((CONFIG / KUROOTO_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    exe = cfg.get("exe") if cfg.get("on") else None
    return exe if exe and Path(exe).exists() else None


def kurooto(action: str) -> str:
    import json

    f = CONFIG / KUROOTO_FILE
    if action == "on":
        exe = shutil.which("kurooto") or shutil.which("kurooto.cmd")
        if not exe:
            return "Kurooto isn't installed here (github.com/avtarfr/kurooto)."
        CONFIG.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"on": True, "exe": str(Path(exe).resolve())}), encoding="utf-8")
        tell("Campus login will tell you here about sign-in problems.", key="hello", every=0)
        return "On: sign-in problems now reach you through Kurooto."
    if action == "off":
        f.unlink(missing_ok=True)
        return "Off."
    return "on" if kurooto_cmd() else "off"


def tell(text: str, key: str, every: float = 6 * 3600) -> bool:
    """Send a message through Kurooto, if the integration is on; the same kind of problem at most every 6 hours."""
    import json

    exe = kurooto_cmd()
    if not exe:
        return False
    stamps_file = STATE / "told.json"
    try:
        stamps = json.loads(stamps_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stamps = {}
    if every and time.time() - stamps.get(key, 0) < every:
        return False
    try:
        r = subprocess.run([exe, "notify", "--title", "Campus login", text], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    stamps[key] = time.time()
    STATE.mkdir(parents=True, exist_ok=True)
    stamps_file.write_text(json.dumps(stamps), encoding="utf-8")
    return r.returncode == 0


# --------------------------------------------------------------------------------------------- portal
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def probe() -> str:
    """'online' (the internet answered), 'portal' (the campus page intercepted it) or 'offline'."""
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(PROBE, timeout=8) as r:  # noqa: S310 (a fixed http URL: captive-portal check)
            if r.status == 204:
                return "online"
            body = r.read(65536).decode("utf-8", "replace")
            return "portal" if HOST in body or "8090" in body else "offline"
    except urllib.error.HTTPError as e:  # a redirect to the portal lands here
        loc = e.headers.get("Location", "") if e.headers else ""
        body = ""
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            pass
        return "portal" if HOST in loc or HOST in body else "offline"
    except (OSError, http.client.HTTPException):
        return "offline"


def portal(method: str, path: str, form: dict | None = None) -> str:
    data = urllib.parse.urlencode(form or {}).encode() if method == "POST" else None
    req = urllib.request.Request(  # noqa: S310 (the campus portal's https address, or a test's)
        f"{PORTAL}{path}", data=data, method=method, headers={"User-Agent": f"iiser-login/{__version__}"}
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:  # noqa: S310 (the campus portal, https)
        return r.read(65536).decode("utf-8", "replace")


def tag(xml: str, name: str) -> str:
    m = re.search(rf"<{name}>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</{name}>", xml, re.S)
    return m.group(1).strip() if m else ""


def stamp() -> str:
    return str(int(time.time() * 1000))


def login(user: str, pw: str) -> tuple[bool, str]:
    xml = portal(
        "POST", "/login.xml", {"mode": "191", "username": user, "password": pw, "a": stamp(), "producttype": "0"}
    )
    status, msg = tag(xml, "status"), tag(xml, "message").replace("{username}", user)
    return status == "LIVE", msg or status or "no answer"


def keepalive(user: str) -> str:
    q = urllib.parse.urlencode({"mode": "192", "username": user, "a": stamp(), "producttype": "0"})
    return tag(portal("GET", f"/live?{q}"), "ack")  # ack | nack | login_again | live_off


def logout(user: str) -> str:
    form = {"mode": "193", "username": user, "a": stamp(), "producttype": "0"}
    return tag(portal("POST", "/logout.xml", form), "message")


# ---------------------------------------------------------------------------------------------- actions
def sign_in(kc: Keychain) -> bool:
    user, pw = kc.username(), kc.password()
    if not user or not pw:
        log("no credentials saved: run `iiser-login setup`")
        return False
    try:
        ok, msg = login(user, pw)
    except (OSError, http.client.HTTPException) as e:
        log(f"couldn't reach the campus portal: {e}")
        tell(
            "The campus login page asked to sign in, but couldn't be reached. The internet may be down here.",
            key="unreachable",
        )
        return False
    log("signed in" if ok else f"sign-in refused: {msg}")
    if not ok:
        tell(
            f"The campus network refused the sign-in ({msg}). If your password changed, run: iiser-login setup",
            key="refused",
        )
    return ok


def keep(kc: Keychain, once: bool = False) -> None:
    log("keeping the campus network signed in")
    last_live, told = 0.0, False
    while True:
        if not kc.username():
            if not told:
                log("no credentials saved yet: run `iiser-login setup`")
                told = True
        else:
            told = False
            state = probe()
            if state == "portal":
                if sign_in(kc):
                    last_live = time.time()
            elif state == "online" and time.time() - last_live >= LIVE_EVERY:
                try:
                    ack = keepalive(kc.username())
                    last_live = time.time()
                    if ack in ("nack", "login_again"):
                        log("the portal asked to sign in again")
                        sign_in(kc)
                except (OSError, http.client.HTTPException):
                    pass  # off campus: the portal isn't there; nothing to keep alive
        if once:
            return
        time.sleep(60)


# ------------------------------------------------------------------------------------------- autostart
def _launch_cmd() -> list[str]:
    exe = Path(sys.executable)
    if sys.platform == "win32":  # no console window at sign-in
        w = exe.with_name("pythonw.exe")
        exe = w if w.exists() else exe
    return [str(exe), "-m", "iiser_login", "keep"]


def autostart(action: str) -> str:
    cmd = _launch_cmd()
    if sys.platform == "win32":
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            if action == "on":
                winreg.SetValueEx(k, "IISER network login", 0, winreg.REG_SZ, subprocess.list2cmdline(cmd))
                subprocess.Popen(cmd, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW)
                return "On: it runs whenever you sign in (and is running now)."
            if action == "off":
                try:
                    winreg.DeleteValue(k, "IISER network login")
                except FileNotFoundError:
                    pass
                return "Off (stop the running one in Task Manager → pythonw, or sign out and in)."
            try:
                winreg.QueryValueEx(k, "IISER network login")
                return "on"
            except FileNotFoundError:
                return "off"
    if sys.platform == "darwin":
        plist = Path.home() / "Library/LaunchAgents/io.github.avtarfr.iiser-login.plist"
        if action == "on":
            args = "".join(f"<string>{a}</string>" for a in cmd)
            plist.parent.mkdir(parents=True, exist_ok=True)
            plist.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>'
                f"<key>Label</key><string>io.github.avtarfr.iiser-login</string><key>ProgramArguments</key><array>{args}</array>"
                "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n",
                encoding="utf-8",
            )
            subprocess.run(["launchctl", "unload", str(plist)], capture_output=True)
            subprocess.run(["launchctl", "load", str(plist)], capture_output=True)
            return "On: it runs whenever you sign in (and is running now)."
        if action == "off":
            subprocess.run(["launchctl", "unload", str(plist)], capture_output=True)
            plist.unlink(missing_ok=True)
            return "Off."
        return "on" if plist.exists() else "off"
    unit = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd/user/iiser-login.service"
    if action == "on":
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(
            "[Unit]\nDescription=Keep signed in to IISER Pune's network login\nAfter=network-online.target\n\n"
            f"[Service]\nExecStart={subprocess.list2cmdline(cmd)}\nRestart=always\nRestartSec=30\n\n"
            "[Install]\nWantedBy=default.target\n",
            encoding="utf-8",
        )
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        r = subprocess.run(
            ["systemctl", "--user", "enable", "--now", "iiser-login.service"], capture_output=True, text=True
        )
        if r.returncode != 0:
            return f"Wrote {unit}, but systemd said: {r.stderr.strip()[:200]}"
        return "On: it runs whenever you sign in (and is running now)."
    if action == "off":
        subprocess.run(["systemctl", "--user", "disable", "--now", "iiser-login.service"], capture_output=True)
        unit.unlink(missing_ok=True)
        return "Off."
    return "on" if unit.exists() else "off"


# ------------------------------------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    a = sys.argv[1:] if argv is None else argv
    kc = Keychain()
    cmd = a[0] if a else ""
    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if cmd in ("-V", "--version"):
        print(__version__)
        return 0
    if cmd == "setup":
        if "--username" in a and "--password-stdin" in a:  # for other programs (Kurooto's Campus login)
            user = a[a.index("--username") + 1].strip() if a.index("--username") + 1 < len(a) else ""
            pw = sys.stdin.readline().rstrip("\r\n")
        else:
            user = input("Campus username: ").strip()
            pw = getpass.getpass("Campus password (not shown): ")
        if not user or not pw:
            print("Nothing saved.")
            return 1
        where = kc.save(user, pw)
        print(
            "Saved in "
            + (where if where != "file" else f"{kc.fallback} (only your user can read it; no keyring found)")
            + "."
        )
        state = probe()
        if state == "portal":
            print(
                "Signed in."
                if sign_in(kc)
                else "The portal refused: check the username and password (run setup again)."
            )
        else:
            print("Not behind the campus login right now; it will sign in when it is.")
        print("Next: `iiser-login autostart on` to stay signed in automatically.")
        if (
            (shutil.which("kurooto") or shutil.which("kurooto.cmd"))
            and "--password-stdin" not in a
            and not kurooto_cmd()
        ):
            if input("Kurooto is installed: send sign-in problems to it (Telegram)? [Y/n] ").strip().lower() in (
                "",
                "y",
                "yes",
            ):
                print(kurooto("on"))
        return 0
    if cmd == "forget":
        kc.forget()
        print("Forgot the saved credentials.")
        return 0
    if cmd == "keep":
        keep(kc)
        return 0
    if cmd == "status":
        print(f"network: {probe()} (online = signed in or off campus; portal = the campus page is asking)")
        print(f"credentials: {'saved for ' + kc.username() if kc.username() else 'none (iiser-login setup)'}")
        print(f"autostart: {autostart('status')}")
        print(f"kurooto: {kurooto('status')}")
        return 0
    if cmd == "logout":
        if not kc.username():
            print("No credentials saved.")
            return 1
        try:
            print(logout(kc.username()) or "Signed out.")
        except (OSError, http.client.HTTPException) as e:
            print(f"Couldn't reach the campus portal: {e}")
            return 1
        return 0
    if cmd == "kurooto":
        print(kurooto(a[1] if len(a) > 1 and a[1] in ("on", "off", "status") else "status"))
        return 0
    if cmd == "autostart":
        print(autostart(a[1] if len(a) > 1 and a[1] in ("on", "off", "status") else "status"))
        return 0
    if cmd:
        print(__doc__)
        return 2
    state = probe()
    if state == "online":
        print("Already online (signed in, or not on campus).")
        return 0
    if state == "portal":
        return 0 if sign_in(kc) else 1
    print("No internet and no campus login page. Are you connected to campus Wi-Fi or ethernet?")
    return 1


if __name__ == "__main__":
    sys.exit(main())
