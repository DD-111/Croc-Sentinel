# Portable launch: put this script next to factory_ui.py, factory_core.py, factory.env
# Optional: set path to secrets if factory.env lives elsewhere.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $env:FACTORY_DOTENV_PATH) {
    $cand = Join-Path $here "factory.env"
    if (Test-Path $cand) { $env:FACTORY_DOTENV_PATH = $cand }
}
Set-Location $here
python .\factory_ui.py
