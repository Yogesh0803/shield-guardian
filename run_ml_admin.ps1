# Guardian Shield — ML Engine Launcher
# Run this as Administrator for live packet capture and enforcement

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

# Set API key (must match backend/.env ML_API_KEY)
$env:ML_API_KEY = "2f458e6a47ec7e5dacfa7cbc3dda25f68dba874024dac32e1dd988b2c27bf931"
$env:BACKEND_URL = "http://localhost:8000"
$env:PYTHONPATH = $ROOT

Write-Host "Starting Guardian Shield ML Engine (live capture)..." -ForegroundColor Cyan
Write-Host "Backend: $env:BACKEND_URL" -ForegroundColor Gray
Write-Host "Interface: auto-detect (Npcap)" -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop.`n" -ForegroundColor Gray

.\.venv\Scripts\python.exe -m ml.main 2>&1 | Tee-Object -FilePath "ml_engine.log"

Read-Host "Press Enter to exit"
