# iiser-sophos-login

Stay signed in to IISER Pune's campus network login (the Sophos page at `firewall.iiserpune.ac.in:8090`) without
opening it. Once set up, it signs you in whenever the page appears and keeps the session alive, on Windows, macOS
and Linux. Not affiliated with IISER Pune.

## Install
**Windows** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/avtarfr/iiser-sophos-login/v0.1.0/installer/install.ps1 | iex
```
**macOS / Linux**:
```sh
curl -LsSf https://raw.githubusercontent.com/avtarfr/iiser-sophos-login/v0.1.0/installer/install.sh | sh
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
campus it sends the page's keep-alive every 3 minutes. Off campus it does nothing. Log: `log.txt` in
`~/.local/state/iiser-sophos-login` (Linux), `~/Library/Logs/iiser-sophos-login` (macOS) or
`%LOCALAPPDATA%\iiser-sophos-login\state` (Windows).

## With Kurooto
If you use [Kurooto](https://github.com/avtarfr/kurooto) (a personal assistant on your computer that talks to you on
Telegram), `iiser-login kurooto on` sends sign-in problems to you through it: a refused password, or a login page that
can't be reached. Each kind of problem at most once every 6 hours. `iiser-login setup` offers this when Kurooto is
installed; `iiser-login kurooto off` stops it.

Uninstall: `iiser-login autostart off`, `iiser-login kurooto off`, `iiser-login forget`, `uv tool uninstall iiser-sophos-login`.

License: Apache-2.0, © Sumangalam Avtar Sharma. See LICENSE and NOTICE.
