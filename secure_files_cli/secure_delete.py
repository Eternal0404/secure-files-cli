"""
Secure Delete Module

Handles secure file deletion and memory wiping operations.
Supports multiple secure deletion standards and verification.
"""

import os
import stat
import time
import random
import secrets
from typing import Optional, Union, BinaryIO

try:
    import mmap
    MMAP_AVAILABLE = True
except ImportError:
    MMAP_AVAILABLE = False


class SecureDeleteError(Exception):
    """Raised when secure deletion operations fail."""
    pass


def secure_delete_file(
    file_path: str,
    passes: int = 3,
    verify: bool = True,
    method: str = "random"
) -> None:
    """
    Securely delete a file by overwriting it multiple times.
    
    Args:
        file_path: Path to file to delete
        passes: Number of overwrite passes (default: 3)
        verify: Whether to verify deletion (default: True)
        method: Overwrite method (random, zeros, ones, dod5220, gutmann)
        
    Raises:
        SecureDeleteError: If secure deletion fails
    """
    try:
        if not os.path.exists(file_path):
            raise SecureDeleteError(f"File not found: {file_path}")
        
        # Get file info
        file_size = os.path.getsize(file_path)
        
        if file_size == 0:
            # Empty file, just delete
            os.remove(file_path)
            return
        
        # Open file for writing
        try:
            with open(file_path, 'r+b') as f:
                # Perform overwrite passes
                for pass_num in range(passes):
                    pattern = _get_overwrite_pattern(method, pass_num, file_size)
                    _overwrite_file(f, pattern, file_size)
                    
                    # Force write to disk
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Small delay between passes
                    time.sleep(0.01)
        
        except PermissionError:
            # Try to make file writable
            try:
                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
                with open(file_path, 'r+b') as f:
                    for pass_num in range(passes):
                        pattern = _get_overwrite_pattern(method, pass_num, file_size)
                        _overwrite_file(f, pattern, file_size)
                        f.flush()
                        os.fsync(f.fileno())
                        time.sleep(0.01)
            except:
                raise SecureDeleteError(f"Permission denied when overwriting file: {file_path}")
        
        # Verify deletion if requested
        if verify:
            if not _verify_file_wiped(file_path, file_size):
                raise SecureDeleteError(f"Failed to securely wipe file: {file_path}")
        
        # Remove file
        os.remove(file_path)
        
        # Try to remove from directory listing (Unix only)
        try:
            # Rename file to random name first
            dir_path = os.path.dirname(file_path) or '.'
            random_name = f".tmp_{secrets.token_hex(8)}"
            random_path = os.path.join(dir_path, random_name)
            
            # This might fail if file is already deleted, that's ok
            try:
                os.rename(file_path, random_path)
                os.remove(random_path)
            except:
                pass
        except:
            pass  # Best effort
            
    except Exception as e:
        raise SecureDeleteError(f"Secure delete failed for {file_path}: {e}")


def secure_delete_directory(
    directory_path: str,
    passes: int = 3,
    verify: bool = True,
    method: str = "random",
    recursive: bool = True
) -> None:
    """
    Securely delete all files in a directory.
    
    Args:
        directory_path: Path to directory
        passes: Number of overwrite passes
        verify: Whether to verify deletion
        method: Overwrite method
        recursive: Whether to delete subdirectories
        
    Raises:
        SecureDeleteError: If secure deletion fails
    """
    try:
        if not os.path.exists(directory_path):
            raise SecureDeleteError(f"Directory not found: {directory_path}")
        
        if not os.path.isdir(directory_path):
            raise SecureDeleteError(f"Path is not a directory: {directory_path}")
        
        # Get all files
        files_to_delete = []
        
        if recursive:
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_to_delete.append(file_path)
        else:
            for item in os.listdir(directory_path):
                item_path = os.path.join(directory_path, item)
                if os.path.isfile(item_path):
                    files_to_delete.append(item_path)
        
        # Delete files
        for file_path in files_to_delete:
            secure_delete_file(file_path, passes, verify, method)
        
        # Remove empty directories if recursive
        if recursive:
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        os.rmdir(dir_path)
                    except:
                        pass
        
        # Remove root directory if empty
        try:
            if not os.listdir(directory_path):
                os.rmdir(directory_path)
        except:
            pass
            
    except Exception as e:
        raise SecureDeleteError(f"Secure directory delete failed: {e}")


def wipe_memory(data: bytearray) -> None:
    """
    Securely wipe memory by overwriting with random data and zeros.
    
    Args:
        data: Byte array to wipe
    """
    try:
        if not isinstance(data, bytearray):
            return
        
        # First pass: random data
        for i in range(len(data)):
            data[i] = secrets.randbits(8)
        
        # Second pass: complement
        for i in range(len(data)):
            data[i] = ~data[i] & 0xFF
        
        # Third pass: zeros
        for i in range(len(data)):
            data[i] = 0
            
    except:
        # Fallback: just try to zero out
        try:
            for i in range(len(data)):
                data[i] = 0
        except:
            pass


def wipe_file_handle(file_handle: BinaryIO, size: Optional[int] = None) -> None:
    """
    Wipe data from an open file handle.
    
    Args:
        file_handle: Open file handle
        size: Size to wipe (file size if None)
    """
    try:
        if size is None:
            # Get current file position and size
            current_pos = file_handle.tell()
            file_handle.seek(0, 2)  # Seek to end
            size = file_handle.tell()
            file_handle.seek(current_pos)  # Restore position
        
        # Overwrite with zeros
        file_handle.seek(0)
        zero_chunk = b'\x00' * min(8192, size)
        bytes_written = 0
        
        while bytes_written < size:
            chunk_size = min(len(zero_chunk), size - bytes_written)
            file_handle.write(zero_chunk[:chunk_size])
            bytes_written += chunk_size
        
        file_handle.flush()
        
    except Exception:
        pass  # Best effort


def _get_overwrite_pattern(method: str, pass_num: int, file_size: int) -> bytes:
    """Get overwrite pattern for a specific method and pass."""
    method = method.lower()
    
    if method == "zeros":
        return b'\x00' * min(8192, file_size)
    
    elif method == "ones":
        return b'\xFF' * min(8192, file_size)
    
    elif method == "random":
        return secrets.token_bytes(min(8192, file_size))
    
    elif method == "dod5220":
        # DoD 5220.22-M standard
        patterns = [b'\x00', b'\xFF', secrets.token_bytes(8192)]
        return patterns[pass_num % len(patterns)]
    
    elif method == "gutmann":
        # Gutmann method (simplified - first few patterns)
        patterns = [
            secrets.token_bytes(8192),
            b'\x00' * 8192,
            b'\xFF' * 8192,
            bytes([0x55]) * 8192,  # 01010101
            bytes([0xAA]) * 8192,  # 10101010
            bytes([0x92, 0x49, 0x24]) * (8192 // 3),  # 10010010...
        ]
        return patterns[pass_num % len(patterns)]
    
    else:
        # Default to random
        return secrets.token_bytes(min(8192, file_size))


def _overwrite_file(file_handle: BinaryIO, pattern: bytes, file_size: int) -> None:
    """Overwrite file with given pattern."""
    file_handle.seek(0)
    bytes_written = 0
    
    while bytes_written < file_size:
        chunk_size = min(len(pattern), file_size - bytes_written)
        file_handle.write(pattern[:chunk_size])
        bytes_written += chunk_size


def _verify_file_wiped(file_path: str, file_size: int) -> bool:
    """Verify that file has been wiped with zeros."""
    try:
        with open(file_path, 'rb') as f:
            chunk_size = 8192
            bytes_checked = 0
            
            while bytes_checked < file_size:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Check if chunk contains only zeros
                if any(b != 0 for b in chunk):
                    return False
                
                bytes_checked += len(chunk)
        
        return True
        
    except:
        return False


def secure_delete_temp_files(directory: str = None) -> int:
    """
    Securely delete temporary files.
    
    Args:
        directory: Directory to clean (default: system temp)
        
    Returns:
        Number of files deleted
    """
    import tempfile
    
    if directory is None:
        directory = tempfile.gettempdir()
    
    deleted_count = 0
    
    try:
        for item in os.listdir(directory):
            if item.startswith('secure-files-cli'):
                item_path = os.path.join(directory, item)
                
                try:
                    if os.path.isfile(item_path):
                        secure_delete_file(item_path, passes=1, verify=False)
                        deleted_count += 1
                    elif os.path.isdir(item_path):
                        secure_delete_directory(item_path, passes=1, verify=False, recursive=True)
                        deleted_count += 1
                except:
                    pass  # Skip files that can't be deleted
                    
    except:
        pass
    
    return deleted_count


def get_available_methods() -> list:
    """
    Get list of available secure deletion methods.
    
    Returns:
        List of method names
    """
    return [
        "random",
        "zeros", 
        "ones",
        "dod5220",
        "gutmann"
    ]


def estimate_secure_delete_time(file_size: int, passes: int = 3, method: str = "random") -> float:
    """
    Estimate time required for secure deletion.
    
    Args:
        file_size: File size in bytes
        passes: Number of passes
        method: Deletion method
        
    Returns:
        Estimated time in seconds
    """
    # Rough estimates based on typical disk speeds
    # These are very approximate and will vary greatly by hardware
    
    # Base write speed (bytes per second) - conservative estimate
    base_speed = 50 * 1024 * 1024  # 50 MB/s
    
    # Adjust for method complexity
    method_multiplier = {
        "zeros": 1.0,
        "ones": 1.0,
        "random": 1.2,
        "dod5220": 1.3,
        "gutmann": 2.0
    }
    
    multiplier = method_multiplier.get(method.lower(), 1.2)
    
    # Calculate time
    effective_speed = base_speed / multiplier
    time_per_pass = file_size / effective_speed
    total_time = time_per_pass * passes
    
    return total_time


def is_secure_delete_supported(file_path: str) -> bool:
    """
    Check if secure deletion is supported for the given file.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if secure deletion is supported
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return False
        
        # Check if we can open file for writing
        try:
            with open(file_path, 'r+b') as f:
                pass
        except:
            return False
        
        # Check file system support (basic check)
        stat_info = os.stat(file_path)
        
        # Skip special files
        if not stat.S_ISREG(stat_info.st_mode):
            return False
        
        return True
        
    except:
        return False


def create_secure_temp_file(suffix: str = "", prefix: str = "secure-files-cli-") -> str:
    """
    Create a secure temporary file.
    
    Args:
        suffix: File suffix
        prefix: File prefix
        
    Returns:
        Path to temporary file
    """
    import tempfile
    
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)  # Close file descriptor
    
    # Set secure permissions
    try:
        os.chmod(path, 0o600)
    except:
        pass
    
    return path