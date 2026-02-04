$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

python -m pip install --upgrade pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name DiscordErisim --add-data "goodbyedpi-0.2.3rc3-turkey;goodbyedpi-0.2.3rc3-turkey" discord_erisimi_gui.py