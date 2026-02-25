@echo off
:: Guardian Shield Backend - Auto-elevates to Administrator
cd /d "%~dp0"

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd.exe -Verb RunAs -ArgumentList '/c cd /d \"%~dp0\" && \"%~f0\"'"
    exit /b
)

echo ========================================
echo  Guardian Shield Backend (Administrator)
echo ========================================
echo.
echo Admin privileges confirmed.
echo Starting uvicorn on port 8000...
echo.

:: Activate venv if present
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
