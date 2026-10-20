# iiser-sophos-login

Stay signed in to IISER Pune's campus network login (the Sophos page at `firewall.iiserpune.ac.in:8090`) without
opening it. Once set up, it signs you in whenever the page appears and keeps the session alive, on Windows, macOS
and Linux. Not affiliated with IISER Pune.

## Install
**Windows** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/avtarfr/iiser-sophos-login/v0.2.0/installer/install.ps1 | iex
```
**macOS / Linux**:
```sh
curl -LsSf https://raw.githubusercontent.com/avtarfr/iiser-sophos-login/v0.2.0/installer/install.sh | sh
```
It installs [uv](https://docs.astral.sh/uv/) if needed, then `iiser-login` for your user (no admin), asks for your
campus username and password, and turns on autostart. Already have uv? `uv tool install
git+https://github.com/avtarfr/iiser-sophos-login`, then `iiser-login setup` and `iiser-login autostart on`.

## Use
| | |
|---|---|
| `iiser-login` | sign in now, if the campus page is asking |
| `iiser-login status` | on campus? signed in? credentials saved? autostart? |
| `iiser-login logout` | sign out |
| `iiser-login autostart on` / `off` | run in the background whenever you sign in |
| `iiser-login setup` / `forget` | save / delete your credentials |
| `iiser-login interfaces all` / `NAME…` / `off` | Linux: sign in on each campus link itself (see below) |

## Your password
- It's kept in your system's keychain: Windows Credential Manager, the macOS Keychain, or the Secret Service on Linux
  (GNOME Keyring, KWallet). Only on a Linux without one is it a file only your user can read
  (`~/.config/iiser-sophos-login/password`).
- It goes only to the campus portal, over HTTPS with the certificate checked, and is never written to the log.
- On macOS it's handed to Apple's `security` tool to store, so it's briefly visible to other programs of yours on the
  same computer while that runs.

## How it works
Every minute it asks Google's connectivity check (`connectivitycheck.gstatic.com/generate_204`). An answer means
you're online; the campus page instead means it signs you in (the same request the page makes). While online on
campus it sends the page's keep-alive every 3 minutes. Off campus it does nothing.

Some links (campus Wi-Fi) end a session after a fixed time, 30 minutes, whatever the keep-alives say. Once it has
seen two such sessions of the same length in its log, it signs in again 2.5 minutes before the end and looks every
few seconds around it, so the internet doesn't drop. If signing in early doesn't reset the network's clock, it notes
that in the log and just watches closely instead. `IISER_LOGIN_EARLY` sets the lead in seconds (`0` turns it off).

Log: `log.txt` in `~/.local/state/iiser-sophos-login` (Linux), `~/Library/Logs/iiser-sophos-login` (macOS) or
`%LOCALAPPDATA%\iiser-sophos-login\state` (Windows).

## Linux: every campus link, even with a hotspot
By default it signs in over the default route. On a laptop that is on campus Wi-Fi (or ethernet) and a phone's
hotspot at once, the default route is often the hotspot, so the campus link quietly stays signed out.
`iiser-login interfaces all` (or `iiser-login interfaces wlan0 enp3s0`) makes every request go out through each
campus link itself (`SO_BINDTODEVICE`, allowed for normal users since Linux 5.7). A link counts as campus when its own
DNS servers, asked through that link, know `firewall.iiserpune.ac.in`, and that answer is where its sign-in goes;
the certificate is still checked against the portal's name. The link's DNS servers come from NetworkManager or
systemd-resolved (else `/etc/resolv.conf`). `iiser-login status` lists each link; `iiser-login interfaces off` goes
back to the default route. Windows and macOS always use the default route.

## With Kurooto
If you use [Kurooto](https://github.com/avtarfr/kurooto) (a personal assistant on your computer that talks to you on
Telegram), `iiser-login kurooto on` sends sign-in problems to you through it: a refused password, or a login page that
can't be reached. Each kind of problem at most once every 6 hours. `iiser-login setup` offers this when Kurooto is
installed; `iiser-login kurooto off` stops it.

Uninstall: `iiser-login autostart off`, `iiser-login kurooto off`, `iiser-login interfaces off`, `iiser-login forget`, `uv tool uninstall iiser-sophos-login`.

License: Apache-2.0, © Sumangalam Avtar Sharma. See LICENSE and NOTICE.
