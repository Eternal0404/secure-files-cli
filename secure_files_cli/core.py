"""
Core Encryption Module

Handles AES-256-GCM encryption and decryption operations for files and data.
Provides secure streaming encryption with authentication.
"""

import os
import io
from typing import Union, Optional, Tuple, BinaryIO

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .key_derivation import derive_key, generate_salt, KeyDerivationError


class EncryptionError(Exception):
    """Raised when encryption operations fail."""
    pass


class DecryptionError(Exception):
    """Raised when decryption operations fail."""
    pass


# File format: [SALT:32][NONCE:12][TAG:16][ENCRYPTED_DATA:N]
SALT_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16
HEADER_LENGTH = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH


def encrypt_data(
    data: bytes,
    password: Union[str, bytes],
    iterations: int = 200_000,
    hash_algorithm: str = "sha256"
) -> bytes:
    """
    Encrypt data using AES-256-GCM with password-derived key.
    
    Args:
        data: Data to encrypt
        password: Password for key derivation
        iterations: PBKDF2 iterations (default: 200000)
        hash_algorithm: Hash algorithm for PBKDF2
        
    Returns:
        Encrypted data with header
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Generate salt and derive key
        salt = generate_salt(SALT_LENGTH)
        key = derive_key(password, salt, iterations, 32, hash_algorithm)
        
        # Generate nonce and create cipher
        nonce = get_random_bytes(NONCE_LENGTH)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt data and get tag
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Combine header and encrypted data
        encrypted_data = salt + nonce + tag + ciphertext
        
        # Securely wipe key from memory
        if isinstance(key, bytearray):
            key[:] = b'\x00' * len(key)
        
        return encrypted_data
        
    except KeyDerivationError as e:
        raise EncryptionError(f"Key derivation failed: {e}")
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}")


def decrypt_data(
    encrypted_data: bytes,
    password: Union[str, bytes],
    iterations: int = 200_000,
    hash_algorithm: str = "sha256"
) -> bytes:
    """
    Decrypt data using AES-256-GCM with password-derived key.
    
    Args:
        encrypted_data: Encrypted data with header
        password: Password for key derivation
        iterations: PBKDF2 iterations (default: 200000)
        hash_algorithm: Hash algorithm for PBKDF2
        
    Returns:
        Decrypted data
        
    Raises:
        DecryptionError: If decryption fails
    """
    try:
        # Validate minimum length
        if len(encrypted_data) < HEADER_LENGTH:
            raise DecryptionError("Invalid encrypted data format")
        
        # Extract header components
        salt = encrypted_data[:SALT_LENGTH]
        nonce = encrypted_data[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
        tag = encrypted_data[SALT_LENGTH + NONCE_LENGTH:SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH]
        ciphertext = encrypted_data[SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH:]
        
        # Derive key
        key = derive_key(password, salt, iterations, 32, hash_algorithm)
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Securely wipe key from memory
        if isinstance(key, bytearray):
            key[:] = b'\x00' * len(key)
        
        return plaintext
        
    except KeyDerivationError as e:
        raise DecryptionError(f"Key derivation failed: {e}")
    except ValueError as e:
        raise DecryptionError(f"Authentication failed: {e}")
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}")


def encrypt_file(
    input_path: str,
    output_path: str,
    password: Union[str, bytes],
    iterations: int = 200_000,
    hash_algorithm: str = "sha256",
    buffer_size: int = 64 * 1024,
    progress_callback: Optional[callable] = None
) -> None:
    """
    Encrypt a file using AES-256-GCM with streaming.
    
    Args:
        input_path: Path to input file
        output_path: Path to output encrypted file
        password: Password for key derivation
        iterations: PBKDF2 iterations (default: 200000)
        hash_algorithm: Hash algorithm for PBKDF2
        buffer_size: Buffer size for streaming (default: 64KB)
        progress_callback: Optional progress callback function
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Validate input file
        if not os.path.exists(input_path):
            raise EncryptionError(f"Input file not found: {input_path}")
        
        # Generate salt and derive key
        salt = generate_salt(SALT_LENGTH)
        key = derive_key(password, salt, iterations, 32, hash_algorithm)
        
        # Generate nonce and create cipher
        nonce = get_random_bytes(NONCE_LENGTH)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Get file size for progress tracking
        file_size = os.path.getsize(input_path)
        bytes_processed = 0
        
        # Open files
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write header
            outfile.write(salt + nonce)
            
            # Encrypt file in chunks
            while True:
                chunk = infile.read(buffer_size)
                if not chunk:
                    break
                
                # Encrypt chunk
                encrypted_chunk = cipher.encrypt(chunk)
                outfile.write(encrypted_chunk)
                
                # Update progress
                bytes_processed += len(chunk)
                if progress_callback:
                    progress_callback(bytes_processed, file_size)
            
            # Get authentication tag and write it
            tag = cipher.digest()
            outfile.write(tag)
        
        # Securely wipe key from memory
        if isinstance(key, bytearray):
            key[:] = b'\x00' * len(key)
        
    except KeyDerivationError as e:
        raise EncryptionError(f"Key derivation failed: {e}")
    except Exception as e:
        # Clean up output file on error
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        raise EncryptionError(f"File encryption failed: {e}")


def decrypt_file(
    input_path: str,
    output_path: str,
    password: Union[str, bytes],
    iterations: int = 200_000,
    hash_algorithm: str = "sha256",
    buffer_size: int = 64 * 1024,
    progress_callback: Optional[callable] = None
) -> None:
    """
    Decrypt a file using AES-256-GCM with streaming.
    
    Args:
        input_path: Path to encrypted file
        output_path: Path to output decrypted file
        password: Password for key derivation
        iterations: PBKDF2 iterations (default: 200000)
        hash_algorithm: Hash algorithm for PBKDF2
        buffer_size: Buffer size for streaming (default: 64KB)
        progress_callback: Optional progress callback function
        
    Raises:
        DecryptionError: If decryption fails
    """
    try:
        # Validate input file
        if not os.path.exists(input_path):
            raise DecryptionError(f"Input file not found: {input_path}")
        
        # Get file size
        file_size = os.path.getsize(input_path)
        
        # Validate minimum file size
        if file_size < HEADER_LENGTH:
            raise DecryptionError("Invalid encrypted file format")
        
        # Open encrypted file
        with open(input_path, 'rb') as infile:
            # Read header
            salt = infile.read(SALT_LENGTH)
            nonce = infile.read(NONCE_LENGTH)
            
            # Derive key
            key = derive_key(password, salt, iterations, 32, hash_algorithm)
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Calculate encrypted data size (excluding header and tag)
            encrypted_size = file_size - HEADER_LENGTH
            bytes_processed = 0
            
            # Open output file
            with open(output_path, 'wb') as outfile:
                # Decrypt file in chunks
                while bytes_processed < encrypted_size:
                    # Calculate chunk size
                    chunk_size = min(buffer_size, encrypted_size - bytes_processed)
                    chunk = infile.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    # Decrypt chunk
                    decrypted_chunk = cipher.decrypt(chunk)
                    outfile.write(decrypted_chunk)
                    
                    # Update progress
                    bytes_processed += chunk_size
                    if progress_callback:
                        progress_callback(bytes_processed, encrypted_size)
                
                # Read and verify authentication tag
                tag = infile.read(TAG_LENGTH)
                if len(tag) != TAG_LENGTH:
                    raise DecryptionError("Invalid file format: missing authentication tag")
                
                try:
                    cipher.verify(tag)
                except ValueError as e:
                    raise DecryptionError(f"Authentication failed: {e}")
        
        # Securely wipe key from memory
        if isinstance(key, bytearray):
            key[:] = b'\x00' * len(key)
        
    except KeyDerivationError as e:
        raise DecryptionError(f"Key derivation failed: {e}")
    except Exception as e:
        # Clean up output file on error
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        raise DecryptionError(f"File decryption failed: {e}")


def encrypt_stream(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    password: Union[str, bytes],
    iterations: int = 200_000,
    hash_algorithm: str = "sha256",
    buffer_size: int = 64 * 1024
) -> None:
    """
    Encrypt data from input stream to output stream.
    
    Args:
        input_stream: Input binary stream
        output_stream: Output binary stream
        password: Password for key derivation
        iterations: PBKDF2 iterations (default: 200000)
        hash_algorithm: Hash algorithm for PBKDF2
        buffer_size: Buffer size for streaming (default: 64KB)
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Generate salt and derive key
        salt = generate_salt(SALT_LENGTH)
        key = derive_key(password, salt, iterations, 32, hash_algorithm)
        
        # Generate nonce and create cipher
        nonce = get_random_bytes(NONCE_LENGTH)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Write header
        output_stream.write(salt + nonce)
        
        # Encrypt stream in chunks
        while True:
            chunk = input_stream.read(buffer_size)
            if not chunk:
                break
            
            encrypted_chunk = cipher.encrypt(chunk)
            output_stream.write(encrypted_chunk)
        
        # Write authentication tag
        tag = cipher.digest()
        output_stream.write(tag)
        
        # Securely wipe key from memory
        if isinstance(key, bytearray):
            key[:] = b'\x00' * len(key)
        
    except KeyDerivationError as e:
        raise EncryptionError(f"Key derivation failed: {e}")
    except Exception as e:
        raise EncryptionError(f"Stream encryption failed: {e}")


def decrypt_stream(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    password: Union[str, bytes],
    iterations: int = 200_000,
    hash_algorithm: str = "sha256",
    buffer_size: int = 64 * 1024
) -> None:
    """
    Decrypt data from input stream to output stream.
    
    Args:
        input_stream: Input binary stream
        output_stream: Output binary stream
        password: Password for key derivation
        iterations: PBKDF2 iterations (default: 200000)
        hash_algorithm: Hash algorithm for PBKDF2
        buffer_size: Buffer size for streaming (default: 64KB)
        
    Raises:
        DecryptionError: If decryption fails
    """
    try:
        # Read header
        salt = input_stream.read(SALT_LENGTH)
        nonce = input_stream.read(NONCE_LENGTH)
        
        if len(salt) != SALT_LENGTH or len(nonce) != NONCE_LENGTH:
            raise DecryptionError("Invalid stream format")
        
        # Derive key
        key = derive_key(password, salt, iterations, 32, hash_algorithm)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt stream in chunks
        while True:
            chunk = input_stream.read(buffer_size)
            if not chunk:
                break
            
            decrypted_chunk = cipher.decrypt(chunk)
            output_stream.write(decrypted_chunk)
        
        # Read and verify authentication tag
        tag = input_stream.read(TAG_LENGTH)
        if len(tag) != TAG_LENGTH:
            raise DecryptionError("Invalid stream format: missing authentication tag")
        
        try:
            cipher.verify(tag)
        except ValueError as e:
            raise DecryptionError(f"Authentication failed: {e}")
        
        # Securely wipe key from memory
        if isinstance(key, bytearray):
            key[:] = b'\x00' * len(key)
        
    except KeyDerivationError as e:
        raise DecryptionError(f"Key derivation failed: {e}")
    except Exception as e:
        raise DecryptionError(f"Stream decryption failed: {e}")


def get_encrypted_file_info(input_path: str) -> dict:
    """
    Get information about an encrypted file.
    
    Args:
        input_path: Path to encrypted file
        
    Returns:
        Dictionary with file information
        
    Raises:
        EncryptionError: If file analysis fails
    """
    try:
        if not os.path.exists(input_path):
            raise EncryptionError(f"File not found: {input_path}")
        
        file_size = os.path.getsize(input_path)
        
        if file_size < HEADER_LENGTH:
            raise EncryptionError("Invalid encrypted file format")
        
        # Read header
        with open(input_path, 'rb') as f:
            salt = f.read(SALT_LENGTH)
            nonce = f.read(NONCE_LENGTH)
            remaining_size = file_size - HEADER_LENGTH
        
        return {
            'file_size': file_size,
            'header_size': HEADER_LENGTH,
            'encrypted_data_size': remaining_size,
            'salt_length': len(salt),
            'nonce_length': len(nonce),
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2'
        }
        
    except Exception as e:
        raise EncryptionError(f"Failed to analyze encrypted file: {e}")