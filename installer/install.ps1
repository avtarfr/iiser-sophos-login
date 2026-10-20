# Install iiser-login for your user (Windows), then save your credentials and turn on autostart.
#     irm https://raw.githubusercontent.com/avtarfr/iiser-sophos-login/v0.2.0/installer/install.ps1 | iex
$ErrorActionPreference = 'Stop'
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing uv (a small Python manager) for your user...'
    Invoke-RestMethod 'https://astral.sh/uv/0.13.1/install.ps1' | Invoke-Expression
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}
uv tool install --force --python 3.12 'git+https://github.com/avtarfr/iiser-sophos-login@v0.2.0'
iiser-login setup
iiser-login autostart on
