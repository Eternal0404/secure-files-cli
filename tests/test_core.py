"""
Test suite for secure-files-cli core functionality.
"""

import pytest
import os
import tempfile
import shutil
from pathlib import Path

from secure_files_cli.core import encrypt_data, decrypt_data, encrypt_file, decrypt_file
from secure_files_cli.key_derivation import derive_key, generate_salt, validate_password_strength
from secure_files_cli.key_management import generate_keyfile, load_keyfile
from secure_files_cli.compression import compress_data, decompress_data
from secure_files_cli.integrity import get_file_hash, verify_file_hash
from secure_files_cli.utils import format_file_size, get_file_size


class TestCoreFunctionality:
    """Test core encryption/decryption functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_data = b"Hello, World! This is test data for encryption."
        self.test_password = "test_password_123"
        self.test_file = os.path.join(self.temp_dir, "test_file.txt")
        self.encrypted_file = os.path.join(self.temp_dir, "test_file.txt.enc")
        self.decrypted_file = os.path.join(self.temp_dir, "test_file_decrypted.txt")
        
        # Create test file
        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        # Encrypt data
        encrypted = encrypt_data(self.test_data, self.test_password)
        assert encrypted != self.test_data
        assert len(encrypted) > len(self.test_data)
        
        # Decrypt data
        decrypted = decrypt_data(encrypted, self.test_password)
        assert decrypted == self.test_data
    
    def test_encrypt_decrypt_file(self):
        """Test file encryption and decryption."""
        # Encrypt file
        encrypt_file(self.test_file, self.encrypted_file, self.test_password)
        assert os.path.exists(self.encrypted_file)
        assert os.path.getsize(self.encrypted_file) > 0
        
        # Decrypt file
        decrypt_file(self.encrypted_file, self.decrypted_file, self.test_password)
        assert os.path.exists(self.decrypted_file)
        
        # Verify content
        with open(self.decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        assert decrypted_data == self.test_data
    
    def test_different_passwords(self):
        """Test encryption with different passwords."""
        encrypted = encrypt_data(self.test_data, self.test_password)
        
        # Try decrypting with wrong password
        with pytest.raises(Exception):
            decrypt_data(encrypted, "wrong_password")
        
        # Try decrypting with correct password
        decrypted = decrypt_data(encrypted, self.test_password)
        assert decrypted == self.test_data
    
    def test_empty_data(self):
        """Test encryption of empty data."""
        encrypted = encrypt_data(b"", self.test_password)
        decrypted = decrypt_data(encrypted, self.test_password)
        assert decrypted == b""
    
    def test_large_data(self):
        """Test encryption of large data."""
        large_data = b"A" * (1024 * 1024)  # 1MB
        
        encrypted = encrypt_data(large_data, self.test_password)
        decrypted = decrypt_data(encrypted, self.test_password)
        assert decrypted == large_data


class TestKeyDerivation:
    """Test key derivation functionality."""
    
    def test_generate_salt(self):
        """Test salt generation."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        assert len(salt1) == 32
        assert len(salt2) == 32
        assert salt1 != salt2
    
    def test_derive_key(self):
        """Test key derivation."""
        password = "test_password"
        salt = generate_salt()
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert len(key1) == 32
        assert key1 == key2
        
        # Different salt should produce different key
        salt3 = generate_salt()
        key3 = derive_key(password, salt3)
        assert key1 != key3
    
    def test_password_strength_validation(self):
        """Test password strength validation."""
        # Weak password
        weak_result = validate_password_strength("123")
        assert weak_result['strength'] == 'weak'
        
        # Strong password
        strong_result = validate_password_strength("StrongP@ssw0rd123!")
        assert strong_result['strength'] == 'strong'
        
        # Medium password
        medium_result = validate_password_strength("Password123")
        assert medium_result['strength'] in ['medium', 'strong']


class TestKeyManagement:
    """Test key management functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.keyfile_path = os.path.join(self.temp_dir, "test.key")
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_load_keyfile(self):
        """Test keyfile generation and loading."""
        # Generate keyfile
        generate_keyfile(self.keyfile_path, overwrite=True)
        assert os.path.exists(self.keyfile_path)
        
        # Load keyfile
        keyfile = load_keyfile(self.keyfile_path)
        assert keyfile.key_data is not None
        assert len(keyfile.key_data) == 32
        assert keyfile.algorithm == "AES-256"
    
    def test_encrypted_keyfile(self):
        """Test encrypted keyfile."""
        keyfile_password = "keyfile_password"
        
        # Generate encrypted keyfile
        generate_keyfile(
            self.keyfile_path,
            encrypt_keyfile=True,
            keyfile_password=keyfile_password,
            overwrite=True
        )
        
        # Load encrypted keyfile
        keyfile = load_keyfile(self.keyfile_path, keyfile_password)
        assert keyfile.key_data is not None
        assert len(keyfile.key_data) == 32


class TestCompression:
    """Test compression functionality."""
    
    def test_compress_decompress_data(self):
        """Test data compression and decompression."""
        test_data = b"Hello, World! " * 100  # Repetitive data for better compression
        
        # Compress
        compressed = compress_data(test_data, "gzip")
        assert len(compressed) < len(test_data)
        
        # Decompress
        decompressed = decompress_data(compressed, "gzip")
        assert decompressed == test_data
    
    def test_different_algorithms(self):
        """Test different compression algorithms."""
        test_data = b"Test data for compression " * 50
        
        algorithms = ["gzip", "lzma", "bz2"]
        
        for algorithm in algorithms:
            compressed = compress_data(test_data, algorithm)
            decompressed = decompress_data(compressed, algorithm)
            assert decompressed == test_data


class TestIntegrity:
    """Test file integrity functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test_file.txt")
        self.test_data = b"Test data for integrity verification"
        
        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_file_hash(self):
        """Test file hashing."""
        hash1 = get_file_hash(self.test_file, "sha256")
        hash2 = get_file_hash(self.test_file, "sha256")
        
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
        assert hash1 == hash2
        
        # Different algorithm should produce different hash
        hash3 = get_file_hash(self.test_file, "sha1")
        assert hash1 != hash3
    
    def test_verify_file_hash(self):
        """Test file hash verification."""
        correct_hash = get_file_hash(self.test_file, "sha256")
        
        # Verify with correct hash
        assert verify_file_hash(self.test_file, correct_hash, "sha256")
        
        # Verify with incorrect hash
        assert not verify_file_hash(self.test_file, "wrong_hash", "sha256")


class TestUtils:
    """Test utility functions."""
    
    def test_format_file_size(self):
        """Test file size formatting."""
        assert format_file_size(0) == "0 B"
        assert format_file_size(1024) == "1.0 KB"
        assert format_file_size(1024 * 1024) == "1.0 MB"
        assert format_file_size(1024 * 1024 * 1024) == "1.0 GB"
    
    def test_get_file_size(self):
        """Test getting file size."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_data = b"Test data" * 100
            f.write(test_data)
            temp_file = f.name
        
        try:
            size = get_file_size(temp_file)
            assert size == len(test_data)
        finally:
            os.unlink(temp_file)


class TestIntegration:
    """Integration tests for complete workflows."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_files = []
        
        # Create multiple test files
        for i in range(3):
            file_path = os.path.join(self.temp_dir, f"test_file_{i}.txt")
            with open(file_path, 'wb') as f:
                f.write(f"Test data for file {i}".encode() * 100)
            self.test_files.append(file_path)
    
    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_encrypt_decrypt_multiple_files(self):
        """Test encrypting and decrypting multiple files."""
        password = "integration_test_password"
        encrypted_files = []
        decrypted_files = []
        
        # Encrypt all files
        for test_file in self.test_files:
            encrypted_file = test_file + ".enc"
            encrypt_file(test_file, encrypted_file, password)
            encrypted_files.append(encrypted_file)
            assert os.path.exists(encrypted_file)
        
        # Decrypt all files
        for i, encrypted_file in enumerate(encrypted_files):
            decrypted_file = self.test_files[i] + ".dec"
            decrypt_file(encrypted_file, decrypted_file, password)
            decrypted_files.append(decrypted_file)
            assert os.path.exists(decrypted_file)
        
        # Verify all decrypted files
        for i, decrypted_file in enumerate(decrypted_files):
            with open(self.test_files[i], 'rb') as original:
                with open(decrypted_file, 'rb') as decrypted:
                    assert original.read() == decrypted.read()
    
    def test_compression_and_encryption(self):
        """Test compressing and then encrypting files."""
        from secure_files_cli.compression import compress_file, decompress_file
        
        password = "compression_encryption_test"
        
        for test_file in self.test_files:
            # Compress first
            compressed_file = test_file + ".gz"
            compress_file(test_file, compressed_file)
            
            # Then encrypt
            encrypted_file = compressed_file + ".enc"
            encrypt_file(compressed_file, encrypted_file, password)
            
            # Decrypt
            decrypted_compressed = compressed_file + ".dec"
            decrypt_file(encrypted_file, decrypted_compressed, password)
            
            # Decompress
            final_file = test_file + ".final"
            decompress_file(decrypted_compressed, final_file)
            
            # Verify
            with open(test_file, 'rb') as original:
                with open(final_file, 'rb') as final:
                    assert original.read() == final.read()


if __name__ == "__main__":
    pytest.main([__file__])