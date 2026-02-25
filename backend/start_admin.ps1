# Guardian Shield Backend — Auto-Elevating Admin Launcher
# This script will auto-elevate to Administrator if not already running as admin.

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Not running as Administrator. Requesting elevation..." -ForegroundColor Yellow
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -WorkingDirectory $scriptDir
    exit
}

# We are admin — start the backend
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Guardian Shield Backend (Administrator)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Admin privileges: CONFIRMED" -ForegroundColor Green
Write-Host ""

Set-Location $scriptDir

# Activate virtual environment if it exists
$venvActivate = Join-Path $scriptDir "venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    Write-Host "Activating virtual environment..." -ForegroundColor Gray
    & $venvActivate
}

Write-Host "Starting uvicorn on http://0.0.0.0:8000 ..." -ForegroundColor Cyan
Write-Host ""

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Write-Host ""
Write-Host "Server stopped. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
