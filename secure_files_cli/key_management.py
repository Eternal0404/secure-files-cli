"""
Key Management Module

Handles keyfile generation, loading, and management operations.
Supports multiple key formats and secure key storage.
"""

import os
import json
import secrets
import hashlib
from typing import Union, Optional, Dict, Any
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from .key_derivation import KeyDerivationError, secure_compare


class KeyManagementError(Exception):
    """Raised when key management operations fail."""
    pass


class KeyFile:
    """Represents a keyfile with metadata."""
    
    def __init__(
        self,
        key_data: bytes,
        algorithm: str = "AES-256",
        key_format: str = "raw",
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.key_data = key_data
        self.algorithm = algorithm
        self.key_format = key_format
        self.metadata = metadata or {}
        self.created_at = self.metadata.get('created_at')
        self.key_id = self.metadata.get('key_id')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert keyfile to dictionary representation."""
        return {
            'key_data': self.key_data.hex() if self.key_format == 'raw' else self.key_data,
            'algorithm': self.algorithm,
            'key_format': self.key_format,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyFile':
        """Create keyfile from dictionary representation."""
        key_data = bytes.fromhex(data['key_data']) if data['key_format'] == 'raw' else data['key_data']
        return cls(
            key_data=key_data,
            algorithm=data['algorithm'],
            key_format=data['key_format'],
            metadata=data.get('metadata', {})
        )


def generate_keyfile(
    output_path: str,
    key_length: int = 32,
    algorithm: str = "AES-256",
    encrypt_keyfile: bool = False,
    keyfile_password: Optional[Union[str, bytes]] = None,
    overwrite: bool = False
) -> str:
    """
    Generate a new keyfile.
    
    Args:
        output_path: Path to save the keyfile
        key_length: Key length in bytes (default: 32)
        algorithm: Encryption algorithm (default: AES-256)
        encrypt_keyfile: Whether to encrypt the keyfile itself
        keyfile_password: Password for keyfile encryption
        overwrite: Whether to overwrite existing keyfile
        
    Returns:
        Path to generated keyfile
        
    Raises:
        KeyManagementError: If keyfile generation fails
    """
    try:
        # Check if file exists
        if os.path.exists(output_path) and not overwrite:
            raise KeyManagementError(f"Keyfile already exists: {output_path}")
        
        # Generate random key
        key_data = get_random_bytes(key_length)
        
        # Generate key ID
        key_id = hashlib.sha256(key_data).hexdigest()[:16]
        
        # Create metadata
        import datetime
        metadata = {
            'key_id': key_id,
            'created_at': datetime.datetime.utcnow().isoformat(),
            'algorithm': algorithm,
            'key_length': key_length,
            'version': '1.0'
        }
        
        # Create keyfile object
        keyfile = KeyFile(
            key_data=key_data,
            algorithm=algorithm,
            key_format='raw',
            metadata=metadata
        )
        
        # Save keyfile
        if encrypt_keyfile:
            if not keyfile_password:
                raise KeyManagementError("Password required for keyfile encryption")
            save_encrypted_keyfile(keyfile, output_path, keyfile_password)
        else:
            save_keyfile(keyfile, output_path)
        
        return output_path
        
    except Exception as e:
        raise KeyManagementError(f"Failed to generate keyfile: {e}")


def load_keyfile(
    keyfile_path: str,
    keyfile_password: Optional[Union[str, bytes]] = None
) -> KeyFile:
    """
    Load a keyfile from disk.
    
    Args:
        keyfile_path: Path to the keyfile
        keyfile_password: Password if keyfile is encrypted
        
    Returns:
        KeyFile object
        
    Raises:
        KeyManagementError: If keyfile loading fails
    """
    try:
        if not os.path.exists(keyfile_path):
            raise KeyManagementError(f"Keyfile not found: {keyfile_path}")
        
        # Try to load as encrypted first
        try:
            return load_encrypted_keyfile(keyfile_path, keyfile_password)
        except:
            # Fall back to unencrypted
            return load_unencrypted_keyfile(keyfile_path)
            
    except Exception as e:
        raise KeyManagementError(f"Failed to load keyfile: {e}")


def save_keyfile(keyfile: KeyFile, output_path: str) -> None:
    """
    Save a keyfile to disk (unencrypted).
    
    Args:
        keyfile: KeyFile object to save
        output_path: Path to save the keyfile
        
    Raises:
        KeyManagementError: If saving fails
    """
    try:
        # Create directory if needed
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save as JSON
        keyfile_dict = keyfile.to_dict()
        with open(output_path, 'w') as f:
            json.dump(keyfile_dict, f, indent=2)
        
        # Set secure permissions
        try:
            os.chmod(output_path, 0o600)
        except:
            pass  # Permission setting is best-effort
            
    except Exception as e:
        raise KeyManagementError(f"Failed to save keyfile: {e}")


def load_unencrypted_keyfile(keyfile_path: str) -> KeyFile:
    """
    Load an unencrypted keyfile.
    
    Args:
        keyfile_path: Path to the keyfile
        
    Returns:
        KeyFile object
        
    Raises:
        KeyManagementError: If loading fails
    """
    try:
        with open(keyfile_path, 'r') as f:
            keyfile_dict = json.load(f)
        
        return KeyFile.from_dict(keyfile_dict)
        
    except json.JSONDecodeError as e:
        raise KeyManagementError(f"Invalid keyfile format: {e}")
    except Exception as e:
        raise KeyManagementError(f"Failed to load unencrypted keyfile: {e}")


def save_encrypted_keyfile(
    keyfile: KeyFile,
    output_path: str,
    password: Union[str, bytes],
    iterations: int = 100_000
) -> None:
    """
    Save a keyfile with encryption.
    
    Args:
        keyfile: KeyFile object to save
        output_path: Path to save the keyfile
        password: Password for encryption
        iterations: PBKDF2 iterations (default: 100000)
        
    Raises:
        KeyManagementError: If saving fails
    """
    try:
        # Create directory if needed
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Serialize keyfile
        keyfile_data = json.dumps(keyfile.to_dict()).encode('utf-8')
        
        # Generate salt and derive key
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, 32, count=iterations, hmac_hash_module=SHA256)
        
        # Encrypt keyfile data
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(keyfile_data)
        
        # Save encrypted data
        encrypted_data = salt + nonce + tag + ciphertext
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Set secure permissions
        try:
            os.chmod(output_path, 0o600)
        except:
            pass  # Permission setting is best-effort
            
    except Exception as e:
        raise KeyManagementError(f"Failed to save encrypted keyfile: {e}")


def load_encrypted_keyfile(
    keyfile_path: str,
    password: Union[str, bytes],
    iterations: int = 100_000
) -> KeyFile:
    """
    Load an encrypted keyfile.
    
    Args:
        keyfile_path: Path to the keyfile
        password: Password for decryption
        iterations: PBKDF2 iterations (default: 100000)
        
    Returns:
        KeyFile object
        
    Raises:
        KeyManagementError: If loading fails
    """
    try:
        # Read encrypted data
        with open(keyfile_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        # Derive key
        key = PBKDF2(password, salt, 32, count=iterations, hmac_hash_module=SHA256)
        
        # Decrypt data
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Parse keyfile
        keyfile_dict = json.loads(plaintext.decode('utf-8'))
        return KeyFile.from_dict(keyfile_dict)
        
    except ValueError as e:
        raise KeyManagementError(f"Invalid password or corrupted keyfile: {e}")
    except json.JSONDecodeError as e:
        raise KeyManagementError(f"Invalid keyfile format: {e}")
    except Exception as e:
        raise KeyManagementError(f"Failed to load encrypted keyfile: {e}")


def verify_keyfile(keyfile_path: str, keyfile_password: Optional[Union[str, bytes]] = None) -> bool:
    """
    Verify that a keyfile is valid and accessible.
    
    Args:
        keyfile_path: Path to the keyfile
        keyfile_password: Password if keyfile is encrypted
        
    Returns:
        True if keyfile is valid, False otherwise
    """
    try:
        load_keyfile(keyfile_path, keyfile_password)
        return True
    except:
        return False


def rotate_keyfile(
    old_keyfile_path: str,
    new_keyfile_path: str,
    old_password: Optional[Union[str, bytes]] = None,
    new_password: Optional[Union[str, bytes]] = None,
    overwrite: bool = False
) -> str:
    """
    Create a new keyfile and migrate data from old one.
    
    Args:
        old_keyfile_path: Path to old keyfile
        new_keyfile_path: Path to new keyfile
        old_password: Password for old keyfile
        new_password: Password for new keyfile
        overwrite: Whether to overwrite existing new keyfile
        
    Returns:
        Path to new keyfile
        
    Raises:
        KeyManagementError: If rotation fails
    """
    try:
        # Load old keyfile
        old_keyfile = load_keyfile(old_keyfile_path, old_password)
        
        # Generate new key
        new_key_data = get_random_bytes(len(old_keyfile.key_data))
        
        # Create new keyfile with same metadata but new key
        import datetime
        metadata = old_keyfile.metadata.copy()
        metadata.update({
            'key_id': hashlib.sha256(new_key_data).hexdigest()[:16],
            'created_at': datetime.datetime.utcnow().isoformat(),
            'rotated_from': old_keyfile.metadata.get('key_id'),
            'rotation_date': datetime.datetime.utcnow().isoformat()
        })
        
        new_keyfile = KeyFile(
            key_data=new_key_data,
            algorithm=old_keyfile.algorithm,
            key_format=old_keyfile.key_format,
            metadata=metadata
        )
        
        # Save new keyfile
        if new_password:
            save_encrypted_keyfile(new_keyfile, new_keyfile_path, new_password)
        else:
            save_keyfile(new_keyfile, new_keyfile_path)
        
        return new_keyfile_path
        
    except Exception as e:
        raise KeyManagementError(f"Failed to rotate keyfile: {e}")


def list_keyfiles(directory: str) -> list:
    """
    List all keyfiles in a directory.
    
    Args:
        directory: Directory to search
        
    Returns:
        List of keyfile paths
    """
    keyfiles = []
    
    try:
        for file_path in Path(directory).rglob('*.key'):
            keyfiles.append(str(file_path))
        
        for file_path in Path(directory).rglob('*.keyfile'):
            keyfiles.append(str(file_path))
            
    except Exception:
        pass  # Ignore directory access errors
    
    return sorted(keyfiles)


def backup_keyfile(
    keyfile_path: str,
    backup_directory: str,
    keyfile_password: Optional[Union[str, bytes]] = None
) -> str:
    """
    Create a backup of a keyfile.
    
    Args:
        keyfile_path: Path to keyfile to backup
        backup_directory: Directory to store backup
        keyfile_password: Password if keyfile is encrypted
        
    Returns:
        Path to backup file
        
    Raises:
        KeyManagementError: If backup fails
    """
    try:
        # Load keyfile
        keyfile = load_keyfile(keyfile_path, keyfile_password)
        
        # Generate backup filename
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"keyfile_backup_{keyfile.metadata.get('key_id', 'unknown')}_{timestamp}.key"
        backup_path = os.path.join(backup_directory, filename)
        
        # Create backup directory
        os.makedirs(backup_directory, exist_ok=True)
        
        # Save backup
        if keyfile_password:
            save_encrypted_keyfile(keyfile, backup_path, keyfile_password)
        else:
            save_keyfile(keyfile, backup_path)
        
        return backup_path
        
    except Exception as e:
        raise KeyManagementError(f"Failed to backup keyfile: {e}")


def combine_keys(
    keyfile_paths: list,
    output_path: str,
    combination_method: str = "xor"
) -> str:
    """
    Combine multiple keys into one master key.
    
    Args:
        keyfile_paths: List of keyfile paths
        output_path: Path to save combined key
        combination_method: Method to combine keys (xor, concatenate)
        
    Returns:
        Path to combined key file
        
    Raises:
        KeyManagementError: If combination fails
    """
    try:
        if not keyfile_paths:
            raise KeyManagementError("No keyfiles provided")
        
        # Load all keys
        keys = []
        for keyfile_path in keyfile_paths:
            keyfile = load_keyfile(keyfile_path)
            keys.append(keyfile.key_data)
        
        # Combine keys
        if combination_method == "xor":
            # XOR all keys together
            combined_key = bytearray(keys[0])
            for key in keys[1:]:
                for i in range(min(len(combined_key), len(key))):
                    combined_key[i] ^= key[i]
            combined_key = bytes(combined_key)
        elif combination_method == "concatenate":
            # Concatenate all keys
            combined_key = b''.join(keys)
        else:
            raise KeyManagementError(f"Unsupported combination method: {combination_method}")
        
        # Create combined keyfile
        import datetime
        metadata = {
            'key_id': hashlib.sha256(combined_key).hexdigest()[:16],
            'created_at': datetime.datetime.utcnow().isoformat(),
            'combination_method': combination_method,
            'source_key_count': len(keys),
            'version': '1.0'
        }
        
        combined_keyfile = KeyFile(
            key_data=combined_key,
            algorithm="AES-256",
            key_format='raw',
            metadata=metadata
        )
        
        # Save combined key
        save_keyfile(combined_keyfile, output_path)
        
        return output_path
        
    except Exception as e:
        raise KeyManagementError(f"Failed to combine keys: {e}")