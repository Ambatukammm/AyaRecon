@echo off
REM AyaRecon setup launcher for Windows. Made by Ruel.
REM Installs Python dependencies AND auto-installs the external tools
REM (via winget / Chocolatey). Run this as Administrator so tool installers
REM don't get blocked.

echo ========================================
echo   AyaRecon setup - made by Ruel
echo ========================================
echo.
echo This will install AyaRecon's Python libraries and then auto-install
echo the security tools (nmap, Wireshark, etc.) via winget / Chocolatey.
echo TIP: right-click setup.bat and "Run as administrator" for a smooth install.
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    echo Install Python 3.9+ from https://www.python.org/downloads/
    echo and tick "Add Python to PATH" during install.
    pause
    exit /b 1
)

python "%~dp0install.py" %*
echo.
echo To start AyaRecon:  python "%~dp0main.py"
pause
