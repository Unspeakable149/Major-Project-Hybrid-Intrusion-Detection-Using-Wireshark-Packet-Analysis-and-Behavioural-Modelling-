@echo off
cd /d "%~dp0"

echo ===================================================
echo     Hybrid IDS System Initialization
echo ===================================================
echo.

echo [*] Launching AI Backend Engine...
start "AI Engine" cmd /k "cd /d "%~dp0" && python live_backend.py"

echo [*] Launching Streamlit SOC Dashboard...
start "SOC Dashboard" cmd /k "cd /d "%~dp0" && python -m streamlit run app.py"

echo.
echo [*] System launched. You can close this window.
exit
