"""
Integrity Module

Handles file integrity verification, hashing, and checksum operations.
Supports multiple hash algorithms and verification methods.
"""

import os
import hashlib
import json
from typing import Dict, List, Optional, Union, BinaryIO
from pathlib import Path


class IntegrityError(Exception):
    """Raised when integrity operations fail."""
    pass


def get_file_hash(
    file_path: str,
    algorithm: str = "sha256",
    buffer_size: int = 65536
) -> str:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512, etc.)
        buffer_size: Buffer size for reading file
        
    Returns:
        Hexadecimal hash string
        
    Raises:
        IntegrityError: If hashing fails
    """
    try:
        if not os.path.exists(file_path):
            raise IntegrityError(f"File not found: {file_path}")
        
        # Create hash object
        try:
            hash_obj = hashlib.new(algorithm)
        except ValueError:
            raise IntegrityError(f"Unsupported hash algorithm: {algorithm}")
        
        # Read file and update hash
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
        
    except Exception as e:
        raise IntegrityError(f"Failed to hash file {file_path}: {e}")


def get_data_hash(data: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm
        
    Returns:
        Hexadecimal hash string
        
    Raises:
        IntegrityError: If hashing fails
    """
    try:
        try:
            hash_obj = hashlib.new(algorithm)
        except ValueError:
            raise IntegrityError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_obj.update(data)
        return hash_obj.hexdigest()
        
    except Exception as e:
        raise IntegrityError(f"Failed to hash data: {e}")


def verify_file_hash(
    file_path: str,
    expected_hash: str,
    algorithm: str = "sha256",
    buffer_size: int = 65536
) -> bool:
    """
    Verify file hash against expected value.
    
    Args:
        file_path: Path to file
        expected_hash: Expected hash value
        algorithm: Hash algorithm
        buffer_size: Buffer size for reading file
        
    Returns:
        True if hash matches, False otherwise
    """
    try:
        actual_hash = get_file_hash(file_path, algorithm, buffer_size)
        return actual_hash.lower() == expected_hash.lower()
    except:
        return False


def verify_data_hash(data: bytes, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify data hash against expected value.
    
    Args:
        data: Data to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm
        
    Returns:
        True if hash matches, False otherwise
    """
    try:
        actual_hash = get_data_hash(data, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    except:
        return False


def create_checksum_file(
    directory: str,
    output_file: str = "CHECKSUMS",
    algorithm: str = "sha256",
    recursive: bool = True,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None
) -> None:
    """
    Create a checksum file for all files in a directory.
    
    Args:
        directory: Directory to scan
        output_file: Output checksum file name
        algorithm: Hash algorithm
        recursive: Whether to scan recursively
        include_patterns: File patterns to include
        exclude_patterns: File patterns to exclude
        
    Raises:
        IntegrityError: If checksum creation fails
    """
    try:
        if not os.path.exists(directory):
            raise IntegrityError(f"Directory not found: {directory}")
        
        checksums = {}
        
        # Scan directory
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, directory)
                    
                    if _should_include_file(file, include_patterns, exclude_patterns):
                        try:
                            file_hash = get_file_hash(file_path, algorithm)
                            # Use forward slashes for cross-platform compatibility
                            rel_path = rel_path.replace('\\', '/')
                            checksums[rel_path] = file_hash
                        except:
                            pass  # Skip files that can't be hashed
        else:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isfile(item_path):
                    if _should_include_file(item, include_patterns, exclude_patterns):
                        try:
                            file_hash = get_file_hash(item_path, algorithm)
                            rel_path = item.replace('\\', '/')
                            checksums[rel_path] = file_hash
                        except:
                            pass
        
        # Write checksum file
        output_path = os.path.join(directory, output_file)
        with open(output_path, 'w') as f:
            for file_path, file_hash in sorted(checksums.items()):
                f.write(f"{file_hash}  {file_path}\n")
        
    except Exception as e:
        raise IntegrityError(f"Failed to create checksum file: {e}")


def verify_checksum_file(
    checksum_file: str,
    base_directory: Optional[str] = None,
    algorithm: str = "sha256"
) -> Dict[str, bool]:
    """
    Verify files against a checksum file.
    
    Args:
        checksum_file: Path to checksum file
        base_directory: Base directory for files (default: same as checksum file)
        algorithm: Hash algorithm used in checksum file
        
    Returns:
        Dictionary mapping file paths to verification results
        
    Raises:
        IntegrityError: If verification fails
    """
    try:
        if not os.path.exists(checksum_file):
            raise IntegrityError(f"Checksum file not found: {checksum_file}")
        
        if base_directory is None:
            base_directory = os.path.dirname(checksum_file)
        
        results = {}
        
        with open(checksum_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse line (format: "hash  filename")
                parts = line.split('  ', 1)
                if len(parts) != 2:
                    continue
                
                expected_hash, file_path = parts
                file_path = file_path.strip()
                
                # Convert to OS-specific path
                file_path = file_path.replace('/', os.sep)
                full_path = os.path.join(base_directory, file_path)
                
                # Verify file
                if os.path.exists(full_path):
                    try:
                        is_valid = verify_file_hash(full_path, expected_hash, algorithm)
                        results[file_path] = is_valid
                    except:
                        results[file_path] = False
                else:
                    results[file_path] = False
        
        return results
        
    except Exception as e:
        raise IntegrityError(f"Failed to verify checksum file: {e}")


def create_integrity_manifest(
    directory: str,
    output_file: str = "MANIFEST.json",
    algorithm: str = "sha256",
    recursive: bool = True,
    include_metadata: bool = True
) -> None:
    """
    Create a detailed integrity manifest for a directory.
    
    Args:
        directory: Directory to scan
        output_file: Output manifest file name
        algorithm: Hash algorithm
        recursive: Whether to scan recursively
        include_metadata: Whether to include file metadata
        
    Raises:
        IntegrityError: If manifest creation fails
    """
    try:
        if not os.path.exists(directory):
            raise IntegrityError(f"Directory not found: {directory}")
        
        manifest = {
            'version': '1.0',
            'algorithm': algorithm,
            'created_at': None,
            'base_directory': os.path.basename(directory),
            'files': {}
        }
        
        # Add timestamp
        import datetime
        manifest['created_at'] = datetime.datetime.utcnow().isoformat()
        
        # Scan directory
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, directory)
                    
                    try:
                        file_info = _get_file_info(file_path, algorithm, include_metadata)
                        rel_path = rel_path.replace('\\', '/')
                        manifest['files'][rel_path] = file_info
                    except:
                        pass  # Skip files that can't be processed
        else:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isfile(item_path):
                    try:
                        file_info = _get_file_info(item_path, algorithm, include_metadata)
                        rel_path = item.replace('\\', '/')
                        manifest['files'][rel_path] = file_info
                    except:
                        pass
        
        # Write manifest
        output_path = os.path.join(directory, output_file)
        with open(output_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
    except Exception as e:
        raise IntegrityError(f"Failed to create integrity manifest: {e}")


def verify_integrity_manifest(
    manifest_file: str,
    base_directory: Optional[str] = None
) -> Dict[str, Dict[str, Union[bool, str]]]:
    """
    Verify files against an integrity manifest.
    
    Args:
        manifest_file: Path to manifest file
        base_directory: Base directory for files
        
    Returns:
        Dictionary with verification results
        
    Raises:
        IntegrityError: If verification fails
    """
    try:
        if not os.path.exists(manifest_file):
            raise IntegrityError(f"Manifest file not found: {manifest_file}")
        
        if base_directory is None:
            base_directory = os.path.dirname(manifest_file)
        
        # Load manifest
        with open(manifest_file, 'r') as f:
            manifest = json.load(f)
        
        algorithm = manifest.get('algorithm', 'sha256')
        results = {}
        
        for file_path, file_info in manifest.get('files', {}).items():
            # Convert to OS-specific path
            file_path = file_path.replace('/', os.sep)
            full_path = os.path.join(base_directory, file_path)
            
            result = {
                'exists': os.path.exists(full_path),
                'hash_valid': False,
                'size_valid': False,
                'modified_valid': False,
                'overall_valid': False
            }
            
            if result['exists']:
                try:
                    # Verify hash
                    expected_hash = file_info.get('hash')
                    if expected_hash:
                        result['hash_valid'] = verify_file_hash(full_path, expected_hash, algorithm)
                    
                    # Verify size
                    if 'size' in file_info:
                        actual_size = os.path.getsize(full_path)
                        result['size_valid'] = actual_size == file_info['size']
                    
                    # Verify modification time
                    if 'modified_time' in file_info:
                        actual_mtime = os.path.getmtime(full_path)
                        result['modified_valid'] = abs(actual_mtime - file_info['modified_time']) < 1
                    
                    # Overall validity
                    result['overall_valid'] = (
                        result['hash_valid'] and
                        result['size_valid'] and
                        result['modified_valid']
                    )
                    
                except:
                    pass  # Keep default values
            
            results[file_path] = result
        
        return results
        
    except Exception as e:
        raise IntegrityError(f"Failed to verify integrity manifest: {e}")


def compare_directories(
    dir1: str,
    dir2: str,
    algorithm: str = "sha256",
    recursive: bool = True
) -> Dict[str, Dict[str, Union[str, bool]]]:
    """
    Compare two directories and find differences.
    
    Args:
        dir1: First directory
        dir2: Second directory
        algorithm: Hash algorithm
        recursive: Whether to compare recursively
        
    Returns:
        Dictionary with comparison results
        
    Raises:
        IntegrityError: If comparison fails
    """
    try:
        if not os.path.exists(dir1):
            raise IntegrityError(f"Directory not found: {dir1}")
        
        if not os.path.exists(dir2):
            raise IntegrityError(f"Directory not found: {dir2}")
        
        # Get file hashes for both directories
        files1 = _get_directory_hashes(dir1, algorithm, recursive)
        files2 = _get_directory_hashes(dir2, algorithm, recursive)
        
        results = {}
        
        # Find all unique files
        all_files = set(files1.keys()) | set(files2.keys())
        
        for file_path in all_files:
            result = {
                'in_dir1': file_path in files1,
                'in_dir2': file_path in files2,
                'hashes_match': False,
                'status': 'different'
            }
            
            if result['in_dir1'] and result['in_dir2']:
                if files1[file_path] == files2[file_path]:
                    result['hashes_match'] = True
                    result['status'] = 'identical'
                else:
                    result['status'] = 'modified'
            elif result['in_dir1'] and not result['in_dir2']:
                result['status'] = 'only_in_dir1'
            elif not result['in_dir1'] and result['in_dir2']:
                result['status'] = 'only_in_dir2'
            
            results[file_path] = result
        
        return results
        
    except Exception as e:
        raise IntegrityError(f"Failed to compare directories: {e}")


def get_available_algorithms() -> List[str]:
    """
    Get list of available hash algorithms.
    
    Returns:
        List of algorithm names
    """
    return sorted(hashlib.algorithms_available)


def benchmark_hash_algorithms(
    test_data: bytes,
    iterations: int = 1000
) -> Dict[str, Dict[str, Union[float, int]]]:
    """
    Benchmark different hash algorithms.
    
    Args:
        test_data: Data to hash for testing
        iterations: Number of iterations per algorithm
        
    Returns:
        Dictionary with benchmark results
    """
    import time
    
    results = {}
    algorithms = get_available_algorithms()
    
    for algorithm in algorithms:
        try:
            # Benchmark
            start_time = time.time()
            
            for _ in range(iterations):
                hash_obj = hashlib.new(algorithm)
                hash_obj.update(test_data)
                hash_obj.hexdigest()
            
            end_time = time.time()
            
            total_time = end_time - start_time
            avg_time = total_time / iterations
            hash_per_second = 1.0 / avg_time if avg_time > 0 else 0
            
            # Get hash size
            test_hash = hashlib.new(algorithm)
            test_hash.update(test_data)
            hash_size = len(test_hash.digest()) * 8  # in bits
            
            results[algorithm] = {
                'total_time': total_time,
                'average_time': avg_time,
                'hashes_per_second': hash_per_second,
                'hash_size_bits': hash_size,
                'iterations': iterations
            }
            
        except:
            # Skip algorithms that don't work
            continue
    
    return results


def _should_include_file(
    filename: str,
    include_patterns: Optional[List[str]],
    exclude_patterns: Optional[List[str]]
) -> bool:
    """Check if file should be included based on patterns."""
    import fnmatch
    
    # Check exclude patterns first
    if exclude_patterns:
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return False
    
    # Check include patterns
    if include_patterns:
        for pattern in include_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False  # No include pattern matched
    
    return True


def _get_file_info(file_path: str, algorithm: str, include_metadata: bool) -> Dict[str, Union[str, int, float]]:
    """Get comprehensive file information."""
    info = {
        'hash': get_file_hash(file_path, algorithm),
        'size': os.path.getsize(file_path)
    }
    
    if include_metadata:
        stat_info = os.stat(file_path)
        info.update({
            'modified_time': stat_info.st_mtime,
            'created_time': stat_info.st_ctime,
            'mode': stat_info.st_mode
        })
    
    return info


def _get_directory_hashes(
    directory: str,
    algorithm: str,
    recursive: bool
) -> Dict[str, str]:
    """Get hashes of all files in a directory."""
    hashes = {}
    
    if recursive:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, directory)
                try:
                    file_hash = get_file_hash(file_path, algorithm)
                    rel_path = rel_path.replace('\\', '/')
                    hashes[rel_path] = file_hash
                except:
                    pass
    else:
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isfile(item_path):
                try:
                    file_hash = get_file_hash(item_path, algorithm)
                    rel_path = item.replace('\\', '/')
                    hashes[rel_path] = file_hash
                except:
                    pass
    
    return hashes