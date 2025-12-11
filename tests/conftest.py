"""
Test configuration and fixtures for pytest.
"""

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_directory():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_file(temp_directory):
    """Create a test file in temporary directory."""
    test_data = b"Hello, World! This is test data."
    file_path = Path(temp_directory) / "test_file.txt"
    
    with open(file_path, 'wb') as f:
        f.write(test_data)
    
    return file_path, test_data


@pytest.fixture
def test_files(temp_directory):
    """Create multiple test files in temporary directory."""
    test_files = []
    test_data = [b"Test data 1", b"Test data 2", b"Test data 3"]
    
    for i, data in enumerate(test_data):
        file_path = Path(temp_directory) / f"test_file_{i}.txt"
        with open(file_path, 'wb') as f:
            f.write(data)
        test_files.append((file_path, data))
    
    return test_files


@pytest.fixture
def sample_password():
    """Sample password for testing."""
    return "test_password_123"


@pytest.fixture
def sample_keyfile(temp_directory):
    """Create a sample keyfile for testing."""
    from secure_files_cli.key_management import generate_keyfile
    
    keyfile_path = Path(temp_directory) / "test.key"
    generate_keyfile(str(keyfile_path), overwrite=True)
    
    return keyfile_path