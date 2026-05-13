@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Hybrid IDS Launcher

REM ---- self-elevate to Administrator (tshark live capture + netsh need it) ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo     Hybrid IDS  -  One-Click Launcher
echo ===================================================
echo.

REM ---- preflight checks ----
set "TSHARK=C:\Program Files\Wireshark\tshark.exe"
if not exist "%TSHARK%" (
    echo [X] tshark not found at "%TSHARK%".
    echo     Install Wireshark or update TSHARK_PATH in live_backend.py.
    pause
    exit /b 1
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python not on PATH. Install Python 3.10+ and retry.
    pause
    exit /b 1
)

if not exist "rf_model.pkl" (
    echo [X] rf_model.pkl missing. Run the training pipeline first:
    echo       python advanced_parser.py
    echo       python feature_engineer.py
    echo       python trainai_rf.py
    pause
    exit /b 1
)

REM ---- launch backend ----
echo [*] Starting backend capture engine...
start "IDS Backend" cmd /k "cd /d ""%~dp0"" && python live_backend.py"

REM ---- launch dashboard ----
echo [*] Starting Streamlit SOC dashboard...
start "IDS Dashboard" cmd /k "cd /d ""%~dp0"" && python -m streamlit run app.py --server.headless true --server.port 8501"

REM ---- wait for Streamlit to bind, then open browser ----
echo [*] Waiting for dashboard to come online...
set "URL=http://localhost:8501"
set /a TRIES=0
:WAIT_LOOP
set /a TRIES+=1
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -TimeoutSec 1).StatusCode } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 goto READY
if %TRIES% geq 20 goto TIMEOUT
timeout /t 1 /nobreak >nul
goto WAIT_LOOP

:READY
echo [+] Dashboard ready at %URL%
start "" "%URL%"
goto DONE

:TIMEOUT
echo [!] Dashboard didn't respond in 20s. Open %URL% manually.

:DONE
echo.
echo [*] System running. Close the two terminal windows to stop.
timeout /t 3 /nobreak >nul
exit /b 0
