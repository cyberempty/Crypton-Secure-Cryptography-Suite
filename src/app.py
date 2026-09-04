#!/usr/bin/env python3

import sys
import os
import hashlib
import struct
import zlib
import time
import threading
import base64
from pathlib import Path
from tkinter import filedialog, messagebox

sys.dont_write_bytecode = True

# ============================================================================
# IMPORTS
# ============================================================================
try:
    import customtkinter as ctk
    from PIL import Image
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Installing dependencies...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter", "Pillow", "cryptography"])
    print("Dependencies installed. Restart the program.")
    sys.exit(0)

try:
    import reedsolo
    RS_AVAILABLE = True
except ImportError:
    RS_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================
MAGIC = b"Crypto"
VERSION = 1
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32

STEGO_MAGIC_LSB = b'STEGO\x00'
STEGO_MAGIC_APP = b'\x00HIDDEN_FILE_START\x00'
STEGO_END_APP = b'\x00HIDDEN_FILE_END\x00'
STEGO_ENCRYPT_MARKER = b'ENCRYPTED_AES256_GCM_'


# ============================================================================
# COLORS
# ============================================================================
COLORS = {
    "bg": "#0a0a0a",
    "bg_secondary": "#121212",
    "bg_tertiary": "#1a1a1a",
    "bg_card": "#181818",
    "text": "#e8e8e8",
    "text_secondary": "#888888",
    "text_muted": "#555555",
    "accent": "#3a3a3a",
    "border": "#252525",
    "border_light": "#2a2a2a",
    "button": "#1e1e1e",
    "button_hover": "#2a2a2a",
    "button_active": "#333333",
    "success": "#2d7a3a",
    "success_hover": "#3a8f4a",
    "danger": "#7a2d2d",
    "danger_hover": "#8f3a3a",
    "warning": "#7a6a2d",
    "warning_hover": "#8f7a3a",
    "info": "#2d4a7a",
    "info_hover": "#3a5a8f",
}

SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_XXL = 4, 8, 12, 16, 24, 32


def setup_theme():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


# ============================================================================
# CRYPTO CORE
# ============================================================================
class CryptoCore:
    """ChaCha20-Poly1305 + Argon2id Encryption"""
    
    def _derive_key(self, password, salt, time_cost=3, memory_cost=64*1024):
        kdf = Argon2id(salt=salt, length=KEY_SIZE, 
                       iterations=time_cost, lanes=4, memory_cost=memory_cost)
        return kdf.derive(password)
    
    def encrypt(self, input_path, output_path, password):
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        plaintext = zlib.compress(plaintext, level=9)
        compressed = True
        
        password_bytes = password.encode('utf-8')
        salt = os.urandom(SALT_SIZE)
        key = self._derive_key(password_bytes, salt)
        
        nonce = os.urandom(NONCE_SIZE)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        header = bytearray()
        header.extend(MAGIC)
        header.extend(struct.pack('<H', VERSION))
        header.extend(struct.pack('<Q', len(plaintext)))
        header.extend(salt)
        header.extend(nonce)
        header.extend(struct.pack('<H', 0))
        header.extend(struct.pack('<Q', int(time.time())))
        
        flags = 0
        if compressed: flags |= 1 << 3
        header.append(flags)
        
        header_hmac = hashlib.sha256(header).digest()[:8]
        header.extend(header_hmac)
        
        with open(output_path, 'wb') as f:
            f.write(header)
            f.write(ciphertext)
        
        return {
            'input': str(input_path), 
            'output': str(output_path),
            'size_original': len(plaintext), 
            'size_encrypted': output_path.stat().st_size
        }
    
    def decrypt(self, input_path, output_path, password):
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        with open(input_path, 'rb') as f:
            magic = f.read(len(MAGIC))
            if magic != MAGIC:
                raise ValueError("Invalid Crypton format")
            
            version = struct.unpack('<H', f.read(2))[0]
            if version != VERSION:
                raise ValueError(f"Unsupported version: {version}")
            
            original_size = struct.unpack('<Q', f.read(8))[0]
            salt = f.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise ValueError("Invalid salt size")
            
            nonce = f.read(NONCE_SIZE)
            if len(nonce) != NONCE_SIZE:
                raise ValueError("Invalid nonce size")
            
            note_len = struct.unpack('<H', f.read(2))[0]
            if note_len != 0:
                f.read(note_len)
            
            timestamp = struct.unpack('<Q', f.read(8))[0]
            flags = f.read(1)[0]
            compressed = bool(flags & 1 << 3)
            
            pos_before_hmac = f.tell()
            stored_hmac = f.read(8)
            
            f.seek(0)
            header_data = f.read(pos_before_hmac)
            if hashlib.sha256(header_data).digest()[:8] != stored_hmac:
                raise ValueError("Corrupt header")
            
            f.seek(pos_before_hmac + 8)
            ciphertext = f.read()
        
        password_bytes = password.encode('utf-8')
        key = self._derive_key(password_bytes, salt)
        cipher = ChaCha20Poly1305(key)
        
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        if compressed:
            plaintext = zlib.decompress(plaintext)
        
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'input': str(input_path), 
            'output': str(output_path)
        }
    
    def verify(self, file_path):
        file_path = Path(file_path)
        with open(file_path, 'rb') as f:
            magic = f.read(len(MAGIC))
            if magic != MAGIC:
                return {'valid': False, 'reason': 'Invalid magic'}
            
            version = struct.unpack('<H', f.read(2))[0]
            if version != VERSION:
                return {'valid': False, 'reason': f'Version: {version}'}
            
            original_size = struct.unpack('<Q', f.read(8))[0]
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            note_len = struct.unpack('<H', f.read(2))[0]
            if note_len > 0:
                f.read(note_len)
            timestamp = struct.unpack('<Q', f.read(8))[0]
            flags = f.read(1)[0]
            pos_before_hmac = f.tell()
            stored_hmac = f.read(8)
            f.seek(0)
            header_data = f.read(pos_before_hmac)
            header_valid = hashlib.sha256(header_data).digest()[:8] == stored_hmac
            
            return {
                'valid': header_valid,
                'version': version,
                'size_original': original_size,
                'timestamp': timestamp,
                'compressed': bool(flags & 1 << 3)
            }


# ============================================================================
# STEGO CORE
# ============================================================================
class StegoCore:
    """LSB/APPEND Steganography"""
    
    def _derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode())), salt
    
    def _encrypt_data(self, data, password):
        key, salt = self._derive_key(password)
        f = Fernet(key)
        return salt + f.encrypt(data)
    
    def _decrypt_data(self, encrypted_data, password):
        salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        key, _ = self._derive_key(password, salt)
        f = Fernet(key)
        return f.decrypt(ciphertext)
    
    def hide_lsb(self, image_path, file_path, output_path, password=None):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        if password:
            encrypted_data = self._encrypt_data(file_data, password)
            file_name = Path(file_path).name.encode('utf-8')
            payload = STEGO_ENCRYPT_MARKER + struct.pack('>H', len(file_name)) + file_name + encrypted_data
        else:
            file_name = Path(file_path).name.encode('utf-8')
            payload = struct.pack('>H', len(file_name)) + file_name + file_data
        
        header = STEGO_MAGIC_LSB + struct.pack('>I', len(payload)) + payload
        img = Image.open(image_path)
        if img.mode in ('RGBA',):
            img = img.convert('RGB')
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        capacity = len(pixels) * (1 if img.mode == 'L' else 3)
        if len(header) * 8 > capacity:
            raise Exception(f"File too large. Max: {capacity//8} bytes")
        
        bits = []
        for byte in header:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        
        new_pixels = []
        bit_idx = 0
        for pixel in pixels:
            if img.mode == 'L':
                if bit_idx < len(bits):
                    new_pixels.append((pixel & 0xFE) | bits[bit_idx])
                    bit_idx += 1
                else:
                    new_pixels.append(pixel)
            else:
                r, g, b = pixel[:3]
                if bit_idx < len(bits):
                    r = (r & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                if bit_idx < len(bits):
                    g = (g & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                if bit_idx < len(bits):
                    b = (b & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                new_pixels.append((r, g, b))
        
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path)
        return True
    
    def extract_lsb(self, image_path):
        img = Image.open(image_path)
        if img.mode in ('RGBA',):
            img = img.convert('RGB')
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')
        pixels = list(img.getdata())
        bits = []
        for pixel in pixels:
            if img.mode == 'L':
                bits.append(pixel & 1)
            else:
                bits.append(pixel[0] & 1)
                bits.append(pixel[1] & 1)
                bits.append(pixel[2] & 1)
        data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
                else:
                    byte = byte << 1
            data.append(byte)
        data = bytes(data)
        pos = data.find(STEGO_MAGIC_LSB)
        if pos == -1:
            return None
        idx = pos + len(STEGO_MAGIC_LSB)
        payload_len = struct.unpack('>I', data[idx:idx+4])[0]
        idx += 4
        return data[idx:idx+payload_len]
    
    def hide_append(self, image_path, file_path, output_path, password=None):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        if password:
            encrypted_data = self._encrypt_data(file_data, password)
            file_name = Path(file_path).name.encode('utf-8')
            payload = STEGO_ENCRYPT_MARKER + struct.pack('>H', len(file_name)) + file_name + encrypted_data
        else:
            file_name = Path(file_path).name.encode('utf-8')
            payload = struct.pack('>H', len(file_name)) + file_name + file_data
        with open(image_path, 'rb') as f:
            image_data = f.read()
        full_payload = STEGO_MAGIC_APP + struct.pack('>I', len(payload)) + payload + STEGO_END_APP
        with open(output_path, 'wb') as f:
            f.write(image_data)
            f.write(full_payload)
        return True
    
    def extract_append(self, image_path):
        with open(image_path, 'rb') as f:
            data = f.read()
        start = data.find(STEGO_MAGIC_APP)
        if start == -1:
            return None
        idx = start + len(STEGO_MAGIC_APP)
        payload_len = struct.unpack('>I', data[idx:idx+4])[0]
        idx += 4
        return data[idx:idx+payload_len]
    
    def is_encrypted(self, payload):
        return payload.startswith(STEGO_ENCRYPT_MARKER)
    
    def process_payload(self, payload, password=None):
        if self.is_encrypted(payload):
            if not password:
                raise Exception("Password required")
            idx = len(STEGO_ENCRYPT_MARKER)
            name_len = struct.unpack('>H', payload[idx:idx+2])[0]
            idx += 2
            file_name = payload[idx:idx+name_len].decode('utf-8')
            idx += name_len
            return file_name, self._decrypt_data(payload[idx:], password)
        else:
            name_len = struct.unpack('>H', payload[:2])[0]
            idx = 2
            file_name = payload[idx:idx+name_len].decode('utf-8')
            idx += name_len
            return file_name, payload[idx:]
    
    def save_file(self, file_name, file_data, output_dir):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        original = Path(file_name)
        path = out / f"{original.stem}_extracted{original.suffix}"
        counter = 1
        while path.exists():
            path = out / f"{original.stem}_{counter}{original.suffix}"
            counter += 1
        with open(path, 'wb') as f:
            f.write(file_data)
        return path


# ============================================================================
# UI WIDGETS
# ============================================================================
class ModernButton(ctk.CTkButton):
    def __init__(self, parent, text, command=None, **kwargs):
        super().__init__(
            parent,
            text=text,
            command=command,
            height=38,
            corner_radius=8,
            font=("Segoe UI", 13),
            fg_color=COLORS["button"],
            hover_color=COLORS["button_hover"],
            text_color=COLORS["text"],
            border_width=0,
            **kwargs
        )


class ModernButtonAccent(ctk.CTkButton):
    def __init__(self, parent, text, command=None, color="success", **kwargs):
        colors = {
            "success": (COLORS["success"], COLORS["success_hover"]),
            "danger": (COLORS["danger"], COLORS["danger_hover"]),
            "warning": (COLORS["warning"], COLORS["warning_hover"]),
            "info": (COLORS["info"], COLORS["info_hover"]),
        }
        fg, hover = colors.get(color, (COLORS["success"], COLORS["success_hover"]))
        super().__init__(
            parent,
            text=text,
            command=command,
            height=38,
            corner_radius=8,
            font=("Segoe UI", 13, "bold"),
            fg_color=fg,
            hover_color=hover,
            text_color=COLORS["text"],
            border_width=0,
            **kwargs
        )


class SidebarButton(ctk.CTkButton):
    def __init__(self, parent, text, command):
        super().__init__(
            parent, 
            text=text, 
            anchor="w", 
            height=44,
            corner_radius=8, 
            font=("Segoe UI", 14),
            fg_color="transparent", 
            hover_color=COLORS["bg_tertiary"],
            text_color=COLORS["text_secondary"], 
            command=command,
            border_width=0
        )
    
    def set_selected(self, selected):
        if selected:
            self.configure(
                fg_color=COLORS["bg_tertiary"], 
                text_color=COLORS["text"], 
                font=("Segoe UI", 14, "bold")
            )
        else:
            self.configure(
                fg_color="transparent", 
                text_color=COLORS["text_secondary"], 
                font=("Segoe UI", 14)
            )


class FilePicker(ctk.CTkFrame):
    def __init__(self, parent, var, placeholder, command):
        super().__init__(parent, fg_color="transparent")
        self.var = var
        self.entry = ctk.CTkEntry(
            self, 
            textvariable=var, 
            placeholder_text=placeholder,
            font=("Segoe UI", 12), 
            height=38,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8,
            text_color=COLORS["text"]
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ModernButton(
            self, 
            text="Browse", 
            width=80,
            command=command
        ).pack(side="left")


# ============================================================================
# MAIN APPLICATION
# ============================================================================
class CryptonApp:
    def __init__(self):
        setup_theme()
        self.root = ctk.CTk()
        self.root.title("Crypton")
        self.root.geometry("1020x800")
        self.root.minsize(920, 720)
        self.root.configure(fg_color=COLORS["bg"])
        
        self.crypto = CryptoCore()
        self.stego = StegoCore()
        self.current_file = None
        
        self.file_path = ctk.StringVar()
        self.password = ctk.StringVar()
        self.confirm_password = ctk.StringVar()
        self.show_password = False
        
        self.stego_show_password = False
        self.extract_show_password = False
        
        self.pages = {}
        self.sidebar_items = {}
        self.current_page = "stego"
        
        self._build_ui()
    
    def _build_ui(self):
        main_container = ctk.CTkFrame(self.root, fg_color=COLORS["bg"])
        main_container.pack(fill="both", expand=True)
        
        sidebar = ctk.CTkFrame(main_container, width=220, fg_color=COLORS["bg_secondary"], corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=16, pady=(20, 16))
        
        ctk.CTkLabel(logo_frame, text="Crypton", font=("Segoe UI", 20, "bold"), text_color=COLORS["text"]).pack()
        
        ctk.CTkFrame(sidebar, height=1, fg_color=COLORS["border"]).pack(fill="x", padx=12, pady=(0, 16))
        
        nav = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav.pack(fill="x", padx=8)
        
        btn_stego = SidebarButton(nav, "Steganography", lambda: self._select_page("stego"))
        btn_stego.pack(fill="x", pady=2)
        self.sidebar_items["stego"] = btn_stego
        
        btn_crypto = SidebarButton(nav, "File Cryptography", lambda: self._select_page("crypto"))
        btn_crypto.pack(fill="x", pady=2)
        self.sidebar_items["crypto"] = btn_crypto
        
        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=16, pady=16)
        ctk.CTkLabel(footer, text="v1.0", font=("Segoe UI", 10), text_color=COLORS["text_muted"]).pack()
        
        content = ctk.CTkFrame(main_container, fg_color=COLORS["bg"])
        content.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        
        self.pages["stego"] = self._build_stego_page(content)
        self.pages["crypto"] = self._build_crypto_page(content)
        self._select_page("stego")
    
    def _select_page(self, name):
        self.current_page = name
        for key, item in self.sidebar_items.items():
            item.set_selected(key == name)
        for key, page in self.pages.items():
            if key == name:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
    
    def _card(self, parent):
        return ctk.CTkFrame(parent, corner_radius=12, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["border_light"])
    
    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def _set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for btn in ['encrypt_btn', 'decrypt_btn', 'verify_btn', 'info_btn', 'hide_btn', 'extract_btn']:
            if hasattr(self, btn):
                getattr(self, btn).configure(state=state)
    
    # ========================================================================
    # STEGO PAGE
    # ========================================================================
    def _build_stego_page(self, parent):
        page = ctk.CTkFrame(parent, fg_color="transparent")
        container = ctk.CTkFrame(page, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=SP_XS, pady=SP_XS)
        
        ctk.CTkLabel(container, text="Steganography", font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(container, text="Hide files inside images using LSB pixel or APPEND method", font=("Segoe UI", 13), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 16))
        
        columns = ctk.CTkFrame(container, fg_color="transparent")
        columns.pack(fill="both", expand=True)
        columns.grid_columnconfigure(0, weight=1)
        columns.grid_columnconfigure(1, weight=1)
        
        # LEFT - Hide
        hide_card = self._card(columns)
        hide_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        hide_inner = ctk.CTkFrame(hide_card, fg_color="transparent")
        hide_inner.pack(fill="both", expand=True, padx=SP_MD, pady=SP_MD)
        
        ctk.CTkLabel(hide_inner, text="Hide File", font=("Segoe UI", 16, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 12))
        
        ctk.CTkLabel(hide_inner, text="File to hide", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_file_var = ctk.StringVar()
        FilePicker(hide_inner, self.hide_file_var, "Select file...", lambda: self._browse_file_var(self.hide_file_var)).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hide_inner, text="Cover image", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_image_var = ctk.StringVar()
        FilePicker(hide_inner, self.hide_image_var, "Select image...", lambda: self._browse_file_var(self.hide_image_var, "image")).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hide_inner, text="Save as", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_output_var = ctk.StringVar()
        FilePicker(hide_inner, self.hide_output_var, "Choose path...", lambda: self._browse_save_var(self.hide_output_var)).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hide_inner, text="Method", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_method_var = ctk.StringVar(value="lsb")
        method_frame = ctk.CTkFrame(hide_inner, fg_color="transparent")
        method_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkRadioButton(method_frame, text="LSB (Pixel)", variable=self.hide_method_var, value="lsb", font=("Segoe UI", 12), fg_color=COLORS["accent"], text_color=COLORS["text"]).pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(method_frame, text="APPEND (End of file)", variable=self.hide_method_var, value="append", font=("Segoe UI", 12), fg_color=COLORS["accent"], text_color=COLORS["text"]).pack(side="left")
        
        self.use_encryption = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(hide_inner, text="Encrypt with AES-256", font=("Segoe UI", 12), variable=self.use_encryption, fg_color=COLORS["bg_tertiary"], progress_color=COLORS["accent"], text_color=COLORS["text"], command=self._toggle_stego_encryption).pack(anchor="w", pady=(0, 6))
        
        # Password row with Show button for Hide
        stego_pass_row = ctk.CTkFrame(hide_inner, fg_color="transparent")
        stego_pass_row.pack(fill="x", pady=2)
        
        self.stego_pass_entry = ctk.CTkEntry(
            stego_pass_row, 
            show="*", 
            placeholder_text="Password",
            font=("Segoe UI", 12), 
            height=34,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8, 
            state="disabled"
        )
        self.stego_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        
        self.stego_show_btn = ModernButton(
            stego_pass_row, 
            text="Show", 
            width=60,
            state="disabled",
            command=self._toggle_stego_password
        )
        self.stego_show_btn.pack(side="right")
        
        self.stego_confirm_entry = ctk.CTkEntry(
            hide_inner, 
            show="*", 
            placeholder_text="Confirm password",
            font=("Segoe UI", 12), 
            height=34,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8, 
            state="disabled"
        )
        self.stego_confirm_entry.pack(fill="x", pady=(0, 10))
        
        self.hide_btn = ModernButtonAccent(hide_inner, text="Hide File", color="success", command=self._do_hide)
        self.hide_btn.pack(fill="x")
        
        # RIGHT - Extract
        extract_card = self._card(columns)
        extract_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        extract_inner = ctk.CTkFrame(extract_card, fg_color="transparent")
        extract_inner.pack(fill="both", expand=True, padx=SP_MD, pady=SP_MD)
        
        ctk.CTkLabel(extract_inner, text="Extract File", font=("Segoe UI", 16, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 12))
        
        ctk.CTkLabel(extract_inner, text="Image with hidden file", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.extract_image_var = ctk.StringVar()
        FilePicker(extract_inner, self.extract_image_var, "Select image...", lambda: self._browse_file_var(self.extract_image_var, "image")).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(extract_inner, text="Destination folder", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.extract_dir_var = ctk.StringVar(value=str(Path.home() / "Desktop"))
        FilePicker(extract_inner, self.extract_dir_var, "Select folder...", lambda: self._browse_dir_var(self.extract_dir_var)).pack(fill="x", pady=(0, 10))
        
        # Password for extract with Show button
        ctk.CTkLabel(extract_inner, text="Password (if encrypted)", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        
        extract_pass_row = ctk.CTkFrame(extract_inner, fg_color="transparent")
        extract_pass_row.pack(fill="x", pady=(0, 10))
        
        self.extract_password = ctk.StringVar()
        self.extract_pass_entry = ctk.CTkEntry(
            extract_pass_row, 
            textvariable=self.extract_password,
            show="*", 
            placeholder_text="Enter password if file is encrypted",
            font=("Segoe UI", 12), 
            height=34,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8,
            text_color=COLORS["text"]
        )
        self.extract_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        
        self.extract_show_btn = ModernButton(
            extract_pass_row, 
            text="Show", 
            width=60,
            command=self._toggle_extract_password
        )
        self.extract_show_btn.pack(side="right")
        
        self.extract_btn = ModernButtonAccent(extract_inner, text="Extract File", color="info", command=self._do_extract)
        self.extract_btn.pack(fill="x", pady=(10, 0))
        
        return page
    
    # ========================================================================
    # CRYPTO PAGE
    # ========================================================================
    def _build_crypto_page(self, parent):
        page = ctk.CTkFrame(parent, fg_color="transparent")
        container = ctk.CTkFrame(page, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=SP_XS, pady=SP_XS)
        
        ctk.CTkLabel(container, text="File Cryptography", font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(container, text="ChaCha20-Poly1305 + Argon2id - Secure file encryption", font=("Segoe UI", 13), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 16))
        
        main_card = self._card(container)
        main_card.pack(fill="both", expand=True)
        main_inner = ctk.CTkFrame(main_card, fg_color="transparent")
        main_inner.pack(fill="both", expand=True, padx=SP_LG, pady=SP_LG)
        
        ctk.CTkLabel(main_inner, text="File", font=("Segoe UI", 13, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        FilePicker(main_inner, self.file_path, "Paste file path or browse...", self._browse_file).pack(fill="x", pady=(0, 6))
        self.file_path.trace_add('write', self._on_file_change)
        
        self.file_info_frame = ctk.CTkFrame(main_inner, fg_color="transparent")
        self.file_info_frame.pack(fill="x")
        self.file_info_frame.pack_forget()
        self.file_info_label = ctk.CTkLabel(self.file_info_frame, text="", font=("Segoe UI", 10), text_color=COLORS["text_secondary"])
        self.file_info_label.pack(side="left")
        self.file_info_icon = ctk.CTkLabel(self.file_info_frame, text="", font=("Segoe UI", 11))
        self.file_info_icon.pack(side="right")
        
        ctk.CTkFrame(main_inner, height=1, fg_color=COLORS["border"]).pack(fill="x", pady=12)
        
        ctk.CTkLabel(main_inner, text="Password", font=("Segoe UI", 13, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        
        pass_row = ctk.CTkFrame(main_inner, fg_color="transparent")
        pass_row.pack(fill="x", pady=(0, 4))
        self.pass_entry = ctk.CTkEntry(pass_row, textvariable=self.password, show="*", height=36, placeholder_text="Enter your password", font=("Segoe UI", 12), border_color=COLORS["border"], border_width=1, corner_radius=8, fg_color=COLORS["bg"])
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.show_btn = ModernButton(pass_row, text="Show", width=60, command=self._toggle_password)
        self.show_btn.pack(side="right")
        
        self.confirm_pass_entry = ctk.CTkEntry(main_inner, textvariable=self.confirm_password, show="*", height=36, placeholder_text="Confirm your password", font=("Segoe UI", 12), border_color=COLORS["border"], border_width=1, corner_radius=8, fg_color=COLORS["bg"])
        self.confirm_pass_entry.pack(fill="x", pady=(0, 6))
        
        ctk.CTkFrame(main_inner, height=1, fg_color=COLORS["border"]).pack(fill="x", pady=12)
        
        btn_row = ctk.CTkFrame(main_inner, fg_color="transparent")
        btn_row.pack(fill="x")
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)
        btn_row.grid_columnconfigure(2, weight=1)
        btn_row.grid_columnconfigure(3, weight=1)
        
        self.encrypt_btn = ModernButtonAccent(btn_row, text="Encrypt", color="success", command=self._encrypt)
        self.encrypt_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        
        self.decrypt_btn = ModernButtonAccent(btn_row, text="Decrypt", color="info", command=self._decrypt)
        self.decrypt_btn.grid(row=0, column=1, sticky="ew", padx=(4, 4))
        
        self.verify_btn = ModernButton(btn_row, text="Verify", command=self._verify)
        self.verify_btn.grid(row=0, column=2, sticky="ew", padx=(4, 4))
        
        self.info_btn = ModernButton(btn_row, text="Info", command=self._show_info)
        self.info_btn.grid(row=0, column=3, sticky="ew", padx=(4, 0))
        
        return page
    
    # ========================================================================
    # STEGO HELPERS
    # ========================================================================
    def _toggle_stego_encryption(self):
        state = "normal" if self.use_encryption.get() else "disabled"
        self.stego_pass_entry.configure(state=state)
        self.stego_confirm_entry.configure(state=state)
        self.stego_show_btn.configure(state=state)
        if state == "disabled":
            self.stego_show_password = False
            self.stego_pass_entry.configure(show="*")
            self.stego_confirm_entry.configure(show="*")
            self.stego_show_btn.configure(text="Show")
            self.stego_pass_entry.delete(0, "end")
            self.stego_confirm_entry.delete(0, "end")
    
    def _toggle_stego_password(self):
        """Mostra/nasconde entrambe le password nella sezione Hide"""
        self.stego_show_password = not self.stego_show_password
        if self.stego_show_password:
            self.stego_pass_entry.configure(show="")
            self.stego_confirm_entry.configure(show="")
            self.stego_show_btn.configure(text="Hide")
        else:
            self.stego_pass_entry.configure(show="*")
            self.stego_confirm_entry.configure(show="*")
            self.stego_show_btn.configure(text="Show")
    
    def _toggle_extract_password(self):
        """Mostra/nasconde la password nella sezione Extract"""
        self.extract_show_password = not self.extract_show_password
        if self.extract_show_password:
            self.extract_pass_entry.configure(show="")
            self.extract_show_btn.configure(text="Hide")
        else:
            self.extract_pass_entry.configure(show="*")
            self.extract_show_btn.configure(text="Show")
    
    def _browse_file_var(self, var, type_="file"):
        if type_ == "image":
            path = filedialog.askopenfilename(title="Select image", filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp *.tiff"), ("All", "*.*")])
        else:
            path = filedialog.askopenfilename(title="Select file", filetypes=[("All", "*.*")])
        if path:
            var.set(path)
    
    def _browse_save_var(self, var):
        path = filedialog.asksaveasfilename(title="Save image", defaultextension=".png", filetypes=[("PNG", "*.png"), ("BMP", "*.bmp"), ("JPEG", "*.jpg"), ("All", "*.*")])
        if path:
            var.set(path)
    
    def _browse_dir_var(self, var):
        path = filedialog.askdirectory(title="Select folder")
        if path:
            var.set(path)
    
    def _do_hide(self):
        img = self.hide_image_var.get()
        fil = self.hide_file_var.get()
        out = self.hide_output_var.get()
        method = self.hide_method_var.get()
        
        if not img:
            messagebox.showerror("Error", "Select a cover image")
            return
        if not fil:
            messagebox.showerror("Error", "Select a file to hide")
            return
        if not out:
            messagebox.showerror("Error", "Specify output path")
            return
        
        password = None
        if self.use_encryption.get():
            password = self.stego_pass_entry.get()
            if not password:
                messagebox.showerror("Error", "Password required")
                return
            if password != self.stego_confirm_entry.get():
                messagebox.showerror("Error", "Passwords do not match")
                return
        
        try:
            if method == "lsb":
                self.stego.hide_lsb(img, fil, out, password)
            else:
                self.stego.hide_append(img, fil, out, password)
            messagebox.showinfo("Success", "File hidden successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _do_extract(self):
        img = self.extract_image_var.get()
        out = self.extract_dir_var.get()
        password = self.extract_password.get()
        
        if not img:
            messagebox.showerror("Error", "Select an image")
            return
        if not out:
            out = str(Path.home() / "Desktop")
            self.extract_dir_var.set(out)
        
        try:
            payload = self.stego.extract_lsb(img)
            if not payload:
                payload = self.stego.extract_append(img)
            if not payload:
                messagebox.showwarning("Warning", "No hidden file found")
                return
            
            if self.stego.is_encrypted(payload):
                if not password:
                    messagebox.showerror("Error", "Password required for encrypted file")
                    return
                try:
                    file_name, file_data = self.stego.process_payload(payload, password)
                except Exception as e:
                    messagebox.showerror("Error", f"Wrong password or corrupted data: {str(e)}")
                    return
            else:
                file_name, file_data = self.stego.process_payload(payload, None)
            
            path = self.stego.save_file(file_name, file_data, out)
            messagebox.showinfo("Success", f"Extracted: {path.name}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    # ========================================================================
    # CRYPTO HELPERS
    # ========================================================================
    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file", filetypes=[("All files", "*.*"), ("Crypton files", "*.crypton")])
        if path:
            self.file_path.set(path)
            self.current_file = Path(path)
            self._update_file_info()
    
    def _toggle_password(self):
        """Mostra/nasconde entrambe le password nella sezione Cryptography"""
        self.show_password = not self.show_password
        if self.show_password:
            self.pass_entry.configure(show="")
            self.confirm_pass_entry.configure(show="")
            self.show_btn.configure(text="Hide")
        else:
            self.pass_entry.configure(show="*")
            self.confirm_pass_entry.configure(show="*")
            self.show_btn.configure(text="Show")
    
    def _on_file_change(self, *args):
        path = self.file_path.get().strip()
        if path and Path(path).exists():
            self.current_file = Path(path)
            self._update_file_info()
        else:
            self.current_file = None
            self.file_info_frame.pack_forget()
    
    def _update_file_info(self):
        if self.current_file and self.current_file.exists():
            size = self.current_file.stat().st_size
            info_text = f"{self.current_file.name} | {self._format_size(size)}"
            if self.current_file.suffix.lower() == '.crypton':
                try:
                    info = self.crypto.verify(self.current_file)
                    if info['valid']:
                        info_text += " | Valid Crypton file"
                except:
                    pass
            self.file_info_frame.pack(fill="x")
            self.file_info_label.configure(text=info_text)
            self.file_info_icon.configure(text="OK", text_color=COLORS["success"])
    
    def _run_async(self, func, *args, **kwargs):
        self._set_buttons_enabled(False)
        
        def wrapper():
            try:
                result = func(*args, **kwargs)
                self.root.after(0, lambda: self._on_operation_done(result, True))
            except Exception as err:
                error_msg = str(err)
                self.root.after(0, lambda: self._on_operation_done(error_msg, False))
        
        threading.Thread(target=wrapper, daemon=True).start()
    
    def _on_operation_done(self, result, success):
        self._set_buttons_enabled(True)
        if success and isinstance(result, dict):
            msg = "Success\n\n"
            msg += f"Input: {result.get('input', 'N/A')}\n"
            msg += f"Output: {result.get('output', 'N/A')}\n"
            if 'size_original' in result:
                msg += f"Original: {self._format_size(result['size_original'])}\n"
            if 'size_encrypted' in result:
                msg += f"Encrypted: {self._format_size(result['size_encrypted'])}\n"
            messagebox.showinfo("Success", msg)
        elif success:
            messagebox.showinfo("Success", "Operation completed successfully!")
        else:
            messagebox.showerror("Error", result)
    
    def _encrypt(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Enter a password")
            return
        if self.password.get() != self.confirm_password.get():
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        default = f"{self.current_file.stem}.crypton"
        output = filedialog.asksaveasfilename(defaultextension=".crypton", initialfile=default, filetypes=[("Crypton files", "*.crypton"), ("All", "*.*")])
        if output:
            self._run_async(self.crypto.encrypt, self.current_file, Path(output), self.password.get())
    
    def _decrypt(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        if self.current_file.suffix.lower() != '.crypton':
            messagebox.showerror("Error", "Not a Crypton file")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Enter the password")
            return
        
        base_name = self.current_file.stem
        
        if '.' in base_name:
            original_name = base_name.rsplit('.', 1)[0]
            original_ext = '.' + base_name.rsplit('.', 1)[1]
            default = f"{original_name}_decrypted{original_ext}"
        else:
            default = f"{base_name}_decrypted"
        
        output = filedialog.asksaveasfilename(
            defaultextension="",
            initialfile=default,
            filetypes=[("All files", "*.*")]
        )
        if output:
            self._run_async(self.crypto.decrypt, self.current_file, Path(output), self.password.get())
    
    def _verify(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        try:
            info = self.crypto.verify(self.current_file)
            if info['valid']:
                msg = "Valid Crypton file\n\n"
                msg += f"Version: {info['version']}\n"
                msg += f"Original Size: {self._format_size(info['size_original'])}\n"
                messagebox.showinfo("Verify", msg)
            else:
                messagebox.showerror("Error", "File is corrupt!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _show_info(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        size = self.current_file.stat().st_size
        info = "File Information\n\n"
        info += f"Name: {self.current_file.name}\n"
        info += f"Size: {self._format_size(size)}\n"
        info += f"Path: {self.current_file.parent}\n"
        if self.current_file.suffix.lower() == '.crypton':
            try:
                cinfo = self.crypto.verify(self.current_file)
                if cinfo['valid']:
                    info += f"\n--- Crypton Metadata ---\n"
                    info += f"Original: {self._format_size(cinfo['size_original'])}"
            except:
                pass
        messagebox.showinfo("File Info", info)
    
    def run(self):
        self.root.mainloop()


# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    app = CryptonApp()
    app.run()