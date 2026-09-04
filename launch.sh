#!/bin/bash

echo "================================================="
echo "   Crypton - Secure Cryptography Suite"
echo "================================================="
echo ""


export PYTHONDONTWRITEBYTECODE=1

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 not found!"
    echo ""
    echo "Please install Python 3.7 or higher"
    echo ""
    read -p "Press Enter to exit..."
    exit 1
fi

echo "[INFO] Python found:"
python3 --version
echo ""

echo "[INFO] Checking dependencies..."
python3 -c "import customtkinter" 2>/dev/null || pip3 install customtkinter --quiet
python3 -c "import PIL" 2>/dev/null || pip3 install Pillow --quiet
python3 -c "import cryptography" 2>/dev/null || pip3 install cryptography --quiet
python3 -c "import reedsolo" 2>/dev/null || pip3 install reedsolo --quiet
echo ""

echo "[INFO] Starting Crypton..."
echo ""

python3 src/launcher.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Failed to start Crypton."
    echo ""
    read -p "Press Enter to exit..."
    exit 1
fi

exit 0