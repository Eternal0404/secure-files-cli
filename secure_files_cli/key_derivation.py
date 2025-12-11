"""
Key Derivation Module

Handles secure key derivation using PBKDF2 with configurable parameters.
Supports multiple hash algorithms and provides salt generation.
"""

import os
import hashlib
import secrets
from typing import Union, Optional

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512


class KeyDerivationError(Exception):
    """Raised when key derivation fails."""
    pass


def generate_salt(length: int = 32) -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Args:
        length: Salt length in bytes (default: 32)
        
    Returns:
        Random salt bytes
        
    Raises:
        KeyDerivationError: If salt generation fails
    """
    try:
        return secrets.token_bytes(length)
    except Exception as e:
        raise KeyDerivationError(f"Failed to generate salt: {e}")


def derive_key(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = 200_000,
    key_length: int = 32,
    hash_algorithm: str = "sha256"
) -> bytes:
    """
    Derive a cryptographic key from password using PBKDF2.
    
    Args:
        password: Password string or bytes
        salt: Random salt bytes
        iterations: Number of PBKDF2 iterations (default: 200000)
        key_length: Derived key length in bytes (default: 32)
        hash_algorithm: Hash algorithm to use (sha256, sha512)
        
    Returns:
        Derived key bytes
        
    Raises:
        KeyDerivationError: If key derivation fails
    """
    try:
        # Convert password to bytes if needed
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
            
        # Select hash module
        if hash_algorithm.lower() == "sha256":
            hash_module = SHA256
        elif hash_algorithm.lower() == "sha512":
            hash_module = SHA512
        else:
            raise KeyDerivationError(f"Unsupported hash algorithm: {hash_algorithm}")
            
        # Derive key using PBKDF2
        key = PBKDF2(
            password_bytes,
            salt,
            dkLen=key_length,
            count=iterations,
            hmac_hash_module=hash_module
        )
        
        return key
        
    except Exception as e:
        raise KeyDerivationError(f"Key derivation failed: {e}")


def derive_key_scrypt(
    password: Union[str, bytes],
    salt: bytes,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    key_length: int = 32
) -> bytes:
    """
    Derive a cryptographic key from password using scrypt.
    
    Args:
        password: Password string or bytes
        salt: Random salt bytes
        n: CPU/memory cost parameter (default: 2^14)
        r: Block size parameter (default: 8)
        p: Parallelization parameter (default: 1)
        key_length: Derived key length in bytes (default: 32)
        
    Returns:
        Derived key bytes
        
    Raises:
        KeyDerivationError: If key derivation fails
    """
    try:
        from Crypto.Protocol.KDF import scrypt
        
        # Convert password to bytes if needed
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
            
        # Derive key using scrypt
        key = scrypt(
            password_bytes,
            salt,
            key_len=key_length,
            N=n,
            r=r,
            p=p
        )
        
        return key
        
    except ImportError:
        raise KeyDerivationError("scrypt not available in this PyCryptodome installation")
    except Exception as e:
        raise KeyDerivationError(f"scrypt key derivation failed: {e}")


def validate_password_strength(password: Union[str, bytes]) -> dict:
    """
    Validate password strength and return metrics.
    
    Args:
        password: Password to validate
        
    Returns:
        Dictionary with strength metrics
    """
    if isinstance(password, bytes):
        password_str = password.decode('utf-8', errors='ignore')
    else:
        password_str = password
        
    metrics = {
        'length': len(password_str),
        'has_lowercase': any(c.islower() for c in password_str),
        'has_uppercase': any(c.isupper() for c in password_str),
        'has_digits': any(c.isdigit() for c in password_str),
        'has_special': any(not c.isalnum() for c in password_str),
        'entropy': calculate_password_entropy(password_str),
        'strength': 'weak'
    }
    
    # Calculate overall strength
    score = 0
    if metrics['length'] >= 8:
        score += 1
    if metrics['length'] >= 12:
        score += 1
    if metrics['has_lowercase']:
        score += 1
    if metrics['has_uppercase']:
        score += 1
    if metrics['has_digits']:
        score += 1
    if metrics['has_special']:
        score += 1
    if metrics['entropy'] >= 50:
        score += 1
        
    if score >= 6:
        metrics['strength'] = 'strong'
    elif score >= 4:
        metrics['strength'] = 'medium'
    else:
        metrics['strength'] = 'weak'
        
    return metrics


def calculate_password_entropy(password: str) -> float:
    """
    Calculate password entropy in bits.
    
    Args:
        password: Password string
        
    Returns:
        Entropy in bits
    """
    if not password:
        return 0.0
        
    # Determine character set size
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32  # Approximate special characters
        
    # Calculate entropy: log2(charset_size^length)
    import math
    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
    
    return entropy


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Securely compare two byte arrays to prevent timing attacks.
    
    Args:
        a: First byte array
        b: Second byte array
        
    Returns:
        True if arrays are equal, False otherwise
    """
    if len(a) != len(b):
        return False
        
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
        
    return result == 0


def wipe_memory(data: bytearray) -> None:
    """
    Securely wipe memory by overwriting with zeros.
    
    Args:
        data: Byte array to wipe
    """
    for i in range(len(data)):
        data[i] = 0