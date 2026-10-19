#!/bin/sh
# Install iiser-login for your user (macOS / Linux), then save your credentials and turn on autostart.
#     curl -LsSf https://raw.githubusercontent.com/avtarfr/iiser-sophos-login/v0.1.0/installer/install.sh | sh
set -eu
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv (a small Python manager) for your user..."
  curl -LsSf https://astral.sh/uv/0.13.1/install.sh | sh >/dev/null
fi
uv tool install --force --python 3.12 "git+https://github.com/avtarfr/iiser-sophos-login@v0.1.0"
iiser-login setup </dev/tty
iiser-login autostart on
