# Crypton – Secure Cryptography Suite

Desktop application (Python + CustomTkinter) for **encrypting files** and **hiding data inside images** (steganography), with a dark-themed graphical interface.

## Features

- **Cryptography**: encrypt/decrypt any file into a proprietary `.crypton` format
  - Algorithm: **ChaCha20-Poly1305** (AEAD) with a key derived from the password via **Argon2id**
  - Automatic compression (zlib) before encryption
  - Header with integrity verified via **HMAC-SHA256**
  - Features: Encrypt, Decrypt, Verify integrity, File info
- **Steganography**: hide a file inside an image (PNG/JPG/BMP/WEBP/TIFF)
  - **LSB** method (least significant bits of pixels) or **Append** (data added at the end of the image file)
  - Optional encryption of the hidden content (PBKDF2 + Fernet/AES) with a password
  - Automatic extraction of the hidden payload, with detection of whether it's encrypted

## Requirements

- Python 3.7+
- Dependencies (see `requirements.txt`):
  - `customtkinter>=5.2.0`
  - `Pillow>=10.0.0`
  - `cryptography>=41.0.0`
  - `reedsolo>=1.5.0` (optional, for error correction)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Launch

**Windows:**
```bash
launch.bat
```

**Linux/Mac:**
```bash
chmod +x launch.sh
./launch.sh
```

Both scripts check for Python and dependencies, installing them automatically if missing, then launch `src/launcher.py`.

Alternatively, direct launch (without automatic checks):
```bash
python app.py
```

## `.crypton` file format

Each encrypted file contains a header with: magic bytes, version, original size, salt, nonce, timestamp, compression flag, and an integrity HMAC, followed by the ciphertext.

## Security notes

- The password is **never stored**: it's only used to derive the encryption key.
- If you lose the password, **the encrypted data cannot be recovered**.
- Use long, complex passwords for real security.