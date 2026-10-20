"""iiser-login: keep your computer signed in to IISER Pune's network login (the Sophos page at
firewall.iiserpune.ac.in:8090), so the internet keeps working on campus Wi-Fi and ethernet without opening the page.

    iiser-login setup            save your campus username and password (in your system's keychain)
                                 (--username NAME --password-stdin: the same, for other programs)
    iiser-login                  sign in now, if the campus page is asking
    iiser-login keep             stay signed in: checks every minute, signs in when the page intercepts, and sends the
                                 page's keep-alive every 3 minutes (what `autostart on` runs in the background).
                                 Where the network ends a session after a fixed time whatever the keep-alives say
                                 (campus Wi-Fi: 30 minutes), once it has seen that twice it signs in again 2.5 minutes
                                 before the end, so the internet doesn't drop
    iiser-login status           are you on campus, signed in, and are credentials saved
    iiser-login logout           sign out
    iiser-login autostart on|off|status    run `keep` whenever you sign in to this computer
    iiser-login forget           delete the saved credentials
    iiser-login kurooto on|off|status    tell you about sign-in problems through Kurooto (Telegram), if you use it
    iiser-login interfaces all|NAME...|off|status    Linux: sign in on each campus link itself (ethernet, campus
                                 Wi-Fi) even when the default route is elsewhere, e.g. a phone's hotspot

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
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

__version__ = "0.2.0"
HOST, PORT = "firewall.iiserpune.ac.in", 8090
PORTAL = os.environ.get("IISER_LOGIN_PORTAL", f"https://{HOST}:{PORT}")  # tests point this at a fake
PROBE = os.environ.get("IISER_LOGIN_PROBE", "http://connectivitycheck.gstatic.com/generate_204")
SERVICE = "iiser-sophos-login"
LIVE_EVERY = 180  # the portal's own page sends a keep-alive every 180 s
EARLY = float(os.environ.get("IISER_LOGIN_EARLY") or 150)  # sign in again this long before a fixed limit (0: don't)
DNS_PORT = 53  # tests point this at a fake
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)  # Linux


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


# ---------------------------------------------------------------------------------------------- links
# By default every request takes the default route, which is all most people need. On Linux, `iiser-login interfaces`
# makes each request go out through a campus link itself (SO_BINDTODEVICE), so a laptop on both campus Wi-Fi and a
# phone's hotspot (or on ethernet and Wi-Fi at once) keeps every campus link signed in. A link counts as campus when
# its own DNS servers, asked through that link, know the firewall's name; that address is where its sign-in goes.
_dns_cache: dict[str, tuple[str | None, float]] = {}  # interface -> (the firewall's address or None, when checked)
_warned: set[str] = set()


def bind_to() -> list[str] | None:
    """The interfaces to sign in through, or None for the default route (the setting is Linux only)."""
    try:
        words = (CONFIG / "interfaces").read_text(encoding="utf-8").split()
    except OSError:
        return None
    if not words or not sys.platform.startswith("linux"):
        return None
    return connected_links() if words == ["all"] else words


def connected_links() -> list[str]:
    """Connected ethernet and Wi-Fi interfaces: from NetworkManager, else the physical ones that are up."""
    if shutil.which("nmcli"):
        try:
            out = subprocess.run(
                ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"], capture_output=True, text=True, timeout=10
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        rows = [(line.split(":") + ["", ""])[:3] for line in out.splitlines()]
        return [d for d, t, s in rows if t in ("ethernet", "wifi") and s.startswith("connected")]
    found = []
    for p in sorted(Path("/sys/class/net").glob("*")):
        try:
            up = (p / "operstate").read_text().strip() == "up"
            ether = (p / "type").read_text().strip() == "1"  # ethernet and Wi-Fi alike
        except OSError:
            continue
        if up and ether and (p / "device").exists():  # a real device, not a bridge, veth or VPN
            found.append(p.name)
    return found


def link_dns(iface: str) -> list[str]:
    """The DNS servers this link was given (NetworkManager or systemd-resolved), else the system's."""
    ipv4 = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    for cmd in (["nmcli", "-g", "IP4.DNS", "dev", "show", iface], ["resolvectl", "dns", iface]):
        if shutil.which(cmd[0]):
            try:
                found = re.findall(ipv4, subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout)
            except (OSError, subprocess.TimeoutExpired):
                found = []
            if found:
                return found
    try:
        return re.findall(rf"^\s*nameserver\s+({ipv4})", Path("/etc/resolv.conf").read_text(), re.M)
    except OSError:
        return []


def bound(iface: str, kind: int = socket.SOCK_STREAM, timeout: float = 8) -> socket.socket:
    """An IPv4 socket whose traffic leaves through `iface` whatever the routing table says (Linux)."""
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
    except OSError:
        s.close()
        raise
    s.settimeout(timeout)
    return s


def _skip_name(r: bytes, i: int) -> int:
    while r[i]:
        if r[i] & 0xC0 == 0xC0:  # a pointer ends the name
            return i + 2
        i += r[i] + 1
    return i + 1


def dns_a(name: str, server: str, iface: str) -> str | None:
    """One A-record lookup sent to `server` through `iface`; None if it has no address for `name`."""
    qid = int.from_bytes(os.urandom(2), "big")
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = bound(iface, socket.SOCK_DGRAM, 3)
    try:
        s.sendto(q, (server, DNS_PORT))
        r = s.recv(2048)
    finally:
        s.close()
    try:
        rid, flags, qd, an = struct.unpack(">HHHH", r[:8])
        if rid != qid or flags & 0x000F:  # not our answer, or an error (NXDOMAIN...)
            return None
        i = 12
        for _ in range(qd):
            i = _skip_name(r, i) + 4
        for _ in range(an):
            i = _skip_name(r, i)
            typ, _, _, ln = struct.unpack(">HHIH", r[i : i + 10])
            i += 10
            if typ == 1 and ln == 4:
                return socket.inet_ntoa(r[i : i + 4])
            i += ln  # a CNAME on the way
    except (struct.error, IndexError):
        pass
    return None


def firewall_ip(iface: str) -> str | None:
    """The firewall's address if `iface` is a campus link (its own DNS knows the firewall), else None."""
    ip, at = _dns_cache.get(iface, (None, 0.0))
    if time.time() - at < (3600 if ip else 300):
        return ip
    ip = None
    for server in link_dns(iface):
        try:
            ip = dns_a(HOST, server, iface)
        except PermissionError:
            if iface not in _warned:
                _warned.add(iface)
                log(f"{iface}: not allowed to send through it (needs Linux 5.7 or newer, or CAP_NET_RAW)")
            break
        except OSError:
            continue
        if ip:
            break
    _dns_cache[iface] = (ip, time.time())
    return ip


def routes() -> list[tuple[str, str] | None]:
    """Where to sign in: [None] (the default route), or each campus link as (interface, firewall address)."""
    names = bind_to()
    if names is None:
        return [None]
    return [(iface, ip) for iface in names for ip in [firewall_ip(iface)] if ip]


class _BoundHTTP(http.client.HTTPConnection):
    iface, addr = "", None

    def connect(self):
        self.sock = bound(self.iface, timeout=self.timeout)
        self.sock.connect((self.addr or self.host, self.port))


class _BoundHTTPS(http.client.HTTPSConnection):
    iface, addr = "", None

    def connect(self):  # to `addr`, but the certificate must be the portal's own name's
        sock = bound(self.iface, timeout=self.timeout)
        sock.connect((self.addr or self.host, self.port))
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(url: str, iface: str, method: str = "GET", data: bytes | None = None, addr: str | None = None, timeout=8):
    """One request through `iface`, to `addr` when given (the firewall's campus address): (status, Location, body)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        conn = _BoundHTTPS(u.hostname, u.port or 443, timeout=timeout, context=ssl.create_default_context())
    else:
        conn = _BoundHTTP(u.hostname, u.port or 80, timeout=timeout)
    conn.iface, conn.addr = iface, addr
    headers = {"User-Agent": f"iiser-login/{__version__}", "Connection": "close"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, u.path + (f"?{u.query}" if u.query else ""), body=data, headers=headers)
        r = conn.getresponse()
        return r.status, r.getheader("Location") or "", r.read(65536).decode("utf-8", "replace")
    finally:
        conn.close()


# --------------------------------------------------------------------------------------------- portal
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def probe(iface: str | None = None) -> str:
    """'online' (the internet answered), 'portal' (the campus page intercepted it) or 'offline'."""
    if iface:
        try:
            status, loc, body = fetch(PROBE, iface)
        except (OSError, http.client.HTTPException):
            return "offline"
        if status == 204:
            return "online"
        return "portal" if HOST in loc or HOST in body or "8090" in body else "offline"
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


def portal(method: str, path: str, form: dict | None = None, via: tuple[str, str] | None = None) -> str:
    data = urllib.parse.urlencode(form or {}).encode() if method == "POST" else None
    if via:  # through that link, to the address its campus DNS gave for the firewall
        iface, ip = via
        addr = ip if urllib.parse.urlsplit(PORTAL).hostname == HOST else None
        return fetch(f"{PORTAL}{path}", iface, method, data, addr, timeout=10)[2]
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


def login(user: str, pw: str, via: tuple[str, str] | None = None) -> tuple[bool, str]:
    xml = portal(
        "POST", "/login.xml", {"mode": "191", "username": user, "password": pw, "a": stamp(), "producttype": "0"}, via
    )
    status, msg = tag(xml, "status"), tag(xml, "message").replace("{username}", user)
    return status == "LIVE", msg or status or "no answer"


def keepalive(user: str, via: tuple[str, str] | None = None) -> str:
    q = urllib.parse.urlencode({"mode": "192", "username": user, "a": stamp(), "producttype": "0"})
    return tag(portal("GET", f"/live?{q}", via=via), "ack")  # ack | nack | login_again | live_off


def logout(user: str, via: tuple[str, str] | None = None) -> str:
    form = {"mode": "193", "username": user, "a": stamp(), "producttype": "0"}
    return tag(portal("POST", "/logout.xml", form, via), "message")


# ---------------------------------------------------------------------------------------------- actions
def sign_in(kc: Keychain, via: tuple[str, str] | None = None, why: str = "") -> bool:
    user, pw = kc.username(), kc.password()
    on = f"{via[0]}: " if via else ""  # which link, when signing in on each one
    if not user or not pw:
        log("no credentials saved: run `iiser-login setup`")
        return False
    try:
        ok, msg = login(user, pw, via)
    except (OSError, http.client.HTTPException) as e:
        log(f"{on}couldn't reach the campus portal: {e}")
        tell(
            "The campus login page asked to sign in, but couldn't be reached. The internet may be down here.",
            key="unreachable",
        )
        return False
    log(f"{on}signed in{why}" if ok else f"{on}sign-in refused: {msg}")
    if not ok:
        tell(
            f"The campus network refused the sign-in ({msg}). If your password changed, run: iiser-login setup",
            key="refused",
        )
    return ok


def session_limits() -> dict[str, tuple[float, float | None]]:
    """From the log, per link ("" for the default route): (when it was last signed in because the page intercepted,
    the fixed session length it enforces or None). A length is known once the last two gaps between such sign-ins
    agree within 2 minutes and are between 10 minutes and 3 hours."""
    seen: dict[str, list[float]] = {}
    try:
        lines = (STATE / "log.txt").read_text(encoding="utf-8").splitlines()[-400:]
    except OSError:
        lines = []
    for line in lines:
        m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?:(\S+): )?signed in$", line)
        if m:
            seen.setdefault(m.group(2) or "", []).append(dt.datetime.fromisoformat(m.group(1)).timestamp())
    out = {}
    for link, ts in seen.items():
        gaps = [b - a for a, b in zip(ts, ts[1:])][-2:]
        fixed = len(gaps) == 2 and abs(gaps[0] - gaps[1]) <= 120 and all(600 <= g <= 3 * 3600 for g in gaps)
        out[link] = (ts[-1], min(gaps) - 60 if fixed else None)  # -60: a gap includes up to a minute of noticing
    return out


def keep_link(kc: Keychain, via: tuple[str, str] | None, limit_of: dict, last_live: dict, early: dict) -> float:
    """One look at one link: sign in if the page intercepts, ahead of a fixed limit, or keep it alive. Returns how
    soon to look again: every minute, or every 3 s around the end of a fixed-length session."""
    link, iface = (via[0], via[0]) if via else ("", None)
    forced_at, limit = limit_of.get(link, (0.0, None))
    e = early.get(link, {})
    start = max(forced_at, e.get("at", 0.0))
    now = time.time()
    on_campus = via or now - last_live.get(link, 0.0) < 2 * LIVE_EVERY  # the default route may be off campus
    if limit and EARLY > 0 and e.get("works") is not False and on_campus:
        if start + limit - EARLY <= now <= start + limit + 120 and probe(iface) == "online":
            if sign_in(kc, via, f" again, ahead of the {round(limit / 60)}-minute limit"):
                early[link] = e = {"at": time.time(), "works": e.get("works")}
                last_live[link] = time.time()
    state = probe(iface)
    if state == "portal":
        if limit and e.get("at") and time.time() - e["at"] < limit / 2:
            early[link] = e = {"works": False}  # it still ended on the old clock: just look often around the end
            log(f"{link + ': ' if via else ''}signing in early doesn't extend the session here; watching closely")
        if sign_in(kc, via):
            last_live[link] = time.time()
            if e.get("works") is not False:
                early.pop(link, None)
    elif state == "online" and time.time() - last_live.get(link, 0.0) >= LIVE_EVERY:
        try:
            ack = keepalive(kc.username(), via)
            last_live[link] = time.time()
            if ack in ("nack", "login_again"):
                log(f"{link + ': ' if via else ''}the portal asked to sign in again")
                sign_in(kc, via)
        except (OSError, http.client.HTTPException):
            pass  # off campus: the portal isn't there; nothing to keep alive
    if limit:
        left = max(forced_at, early.get(link, {}).get("at", 0.0)) + limit + 60 - time.time()
        if -120 <= left <= 180:
            return 3
    return 60


def keep(kc: Keychain, once: bool = False, rounds: int | None = None) -> None:
    log("keeping the campus network signed in")
    last_live: dict[str, float] = {}
    early: dict[str, dict] = {}  # link -> when it was last signed in ahead of the limit, and whether that helped
    told, n = False, 1 if once else rounds
    while True:
        nap = 60.0
        if not kc.username():
            if not told:
                log("no credentials saved yet: run `iiser-login setup`")
                told = True
        else:
            told = False
            limit_of = session_limits()
            for via in routes():
                nap = min(nap, keep_link(kc, via, limit_of, last_live, early))
        if n is not None:
            n -= 1
            if n <= 0:
                return
        time.sleep(nap)


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


def interfaces(args: list[str]) -> str:
    """Sign in through chosen interfaces (Linux): `all` connected ethernet and Wi-Fi, some by name, or `off`."""
    f = CONFIG / "interfaces"
    if args in ([], ["status"]):
        try:
            words = f.read_text(encoding="utf-8").split()
        except OSError:
            words = []
        if not words:
            return "off (the default route)"
        return "every connected ethernet and Wi-Fi link" if words == ["all"] else " ".join(words)
    if args == ["off"]:
        f.unlink(missing_ok=True)
        return "Off: it signs in over the default route."
    if not sys.platform.startswith("linux"):
        return "Signing in through a chosen interface needs Linux; here it always uses the default route."
    bad = [w for w in args if not re.fullmatch(r"[\w.@-]{1,15}", w) or (w == "all" and len(args) > 1)]
    if bad:
        return f"Not an interface name: {' '.join(bad)} (try `ip link` for the names)."
    CONFIG.mkdir(parents=True, exist_ok=True)
    f.write_text(" ".join(args) + "\n", encoding="utf-8")
    which = "every connected ethernet and Wi-Fi link" if args == ["all"] else " ".join(args)
    return f"On: it signs in on each campus link itself ({which}), whatever the default route."


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
    names = bind_to()
    if cmd == "status":
        if names is None:
            print(f"network: {probe()} (online = signed in or off campus; portal = the campus page is asking)")
        for iface in names or []:
            ip = firewall_ip(iface)
            print(f"{iface}: campus, {probe(iface)} (firewall {ip})" if ip else f"{iface}: not campus")
        if names == []:
            print("no connected ethernet or Wi-Fi")
        print(f"credentials: {'saved for ' + kc.username() if kc.username() else 'none (iiser-login setup)'}")
        print(f"autostart: {autostart('status')}")
        print(f"kurooto: {kurooto('status')}")
        print(f"interfaces: {interfaces([])}")
        return 0
    if cmd == "logout":
        if not kc.username():
            print("No credentials saved.")
            return 1
        try:
            if names is None:
                print(logout(kc.username()) or "Signed out.")
            for via in routes() if names is not None else []:
                print(f"{via[0]}: {logout(kc.username(), via) or 'signed out'}")
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
    if cmd == "interfaces":
        print(interfaces(a[1:]))
        return 0
    if cmd:
        print(__doc__)
        return 2
    if names is not None:  # each campus link on its own
        found, ok = routes(), True
        for via in found:
            if probe(via[0]) == "online":
                print(f"{via[0]}: already signed in")
            else:
                ok = sign_in(kc, via) and ok
        if not found:
            print("No campus link right now (ethernet or campus Wi-Fi).")
        return 0 if found and ok else 1
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
