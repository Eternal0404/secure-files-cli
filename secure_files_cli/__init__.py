"""
Secure Files CLI - Advanced File Encryption Tool

A comprehensive Python CLI tool for encrypting/decrypting files using AES-256-GCM
with password-based key derivation (PBKDF2), key management, compression, and
advanced security features.

Author: Eternal0404
License: MIT
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Eternal0404"
__license__ = "MIT"

from .core import encrypt_file, decrypt_file, encrypt_data, decrypt_data
from .key_derivation import derive_key, generate_salt
from .key_management import generate_keyfile, load_keyfile
from .config import Config
from .utils import secure_delete_file, get_file_hash

__all__ = [
    "encrypt_file",
    "decrypt_file", 
    "encrypt_data",
    "decrypt_data",
    "derive_key",
    "generate_salt",
    "generate_keyfile",
    "load_keyfile",
    "Config",
    "secure_delete_file",
    "get_file_hash",
]