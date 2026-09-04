@echo off
title Crypton Launcher
color 0A

echo ================================================
echo    Crypton - Secure Cryptography Suite
echo ================================================
echo.

set PYTHONDONTWRITEBYTECODE=1

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found!
    echo.
    echo Please install Python 3.7 or higher from:
    echo https://python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [INFO] Python found:
python --version
echo.

echo [INFO] Checking dependencies...
python -c "import customtkinter" 2>nul || pip install customtkinter --quiet
python -c "import PIL" 2>nul || pip install Pillow --quiet
python -c "import cryptography" 2>nul || pip install cryptography --quiet
python -c "import reedsolo" 2>nul || pip install reedsolo --quiet
echo.

echo [INFO] Starting Crypton...
echo.

python src/launcher.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to start Crypton.
    echo.
    pause
    exit /b 1
)

pause