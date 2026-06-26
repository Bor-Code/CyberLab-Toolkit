@echo off
setlocal

title CyberLab Toolkit

cd /d "%~dp0"

echo ============================================================
echo CyberLab Toolkit
echo developed by Bor-Code
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not added to PATH.
    echo Please install Python 3.10 or newer and try again.
    echo.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating virtual environment...
    python -m venv .venv

    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo.
        pause
        exit /b 1
    )
)

echo [INFO] Activating virtual environment...
call ".venv\Scripts\activate.bat"

echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

if exist "requirements.txt" (
    echo [INFO] Installing requirements...
    python -m pip install -r requirements.txt
) else (
    echo [INFO] requirements.txt not found. Installing colorama only...
    python -m pip install colorama
)

echo.
echo [INFO] Starting CyberLab Toolkit...
echo ============================================================
echo.

python main.py

echo.
echo CyberLab Toolkit closed.
pause