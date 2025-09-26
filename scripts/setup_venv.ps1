# Create a single .venv in the repo root and install requirements
param(
    [string]$VenvName = '.venv'
)

python -m venv $VenvName
Write-Host "Created virtualenv: $VenvName"

# Activate in this script (PowerShell)
$activate = Join-Path . $VenvName\Scripts\Activate.ps1
if (Test-Path $activate) {
    & $activate
    Write-Host "Activated $VenvName"
    pip install --upgrade pip
    if (Test-Path "requirements.txt") {
        pip install -r requirements.txt
    }
    else {
        Write-Host "requirements.txt not found; install dependencies manually"
    }
}
else {
    Write-Host "Activation script not found: $activate"
}
