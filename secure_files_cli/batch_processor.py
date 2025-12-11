"""
Batch Processor Module

Handles advanced batch operations for encryption/decryption.
Supports parallel processing, filtering, and progress tracking.
"""

import os
import time
import fnmatch
import threading
from typing import List, Dict, Any, Optional, Callable, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .core import encrypt_file, decrypt_file, EncryptionError, DecryptionError
# from .compression import compress_file, decompress_file, detect_compression_algorithm
from .integrity import get_file_hash, verify_file_hash
from .secure_delete import secure_delete_file


class BatchProcessorError(Exception):
    """Raised when batch processing operations fail."""
    pass


@dataclass
class BatchOperation:
    """Represents a single batch operation."""
    input_path: str
    output_path: str
    operation: str  # 'encrypt', 'decrypt', 'compress', 'decompress'
    options: Dict[str, Any]
    
    def __post_init__(self):
        """Validate operation after initialization."""
        if self.operation not in ['encrypt', 'decrypt', 'compress', 'decompress']:
            raise BatchProcessorError(f"Invalid operation: {self.operation}")


@dataclass
class BatchResult:
    """Represents the result of a batch operation."""
    operation: BatchOperation
    success: bool
    error_message: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    input_size: Optional[int] = None
    output_size: Optional[int] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Get operation duration in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


class BatchProcessor:
    """
    Advanced batch processor for file operations.
    
    Supports parallel processing, filtering, and detailed progress tracking.
    """
    
    def __init__(
        self,
        max_workers: int = 4,
        continue_on_error: bool = False,
        progress_callback: Optional[Callable] = None
    ):
        """
        Initialize batch processor.
        
        Args:
            max_workers: Maximum number of parallel workers
            continue_on_error: Whether to continue processing after errors
            progress_callback: Optional progress callback function
        """
        self.max_workers = max_workers
        self.continue_on_error = continue_on_error
        self.progress_callback = progress_callback
        self.results: List[BatchResult] = []
        self._lock = threading.Lock()
    
    def scan_directory(
        self,
        directory: str,
        operation: str,
        output_directory: Optional[str] = None,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        recursive: bool = True,
        options: Optional[Dict[str, Any]] = None
    ) -> List[BatchOperation]:
        """
        Scan directory for files to process.
        
        Args:
            directory: Directory to scan
            operation: Operation to perform
            output_directory: Output directory (default: same as input)
            include_patterns: File patterns to include
            exclude_patterns: File patterns to exclude
            recursive: Whether to scan recursively
            options: Operation options
            
        Returns:
            List of batch operations
        """
        if not os.path.exists(directory):
            raise BatchProcessorError(f"Directory not found: {directory}")
        
        if not os.path.isdir(directory):
            raise BatchProcessorError(f"Path is not a directory: {directory}")
        
        operations = []
        options = options or {}
        
        # Walk directory
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_process_file(file_path, include_patterns, exclude_patterns):
                        op = self._create_operation(
                            file_path, operation, output_directory, options
                        )
                        if op:
                            operations.append(op)
        else:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isfile(item_path):
                    if self._should_process_file(item_path, include_patterns, exclude_patterns):
                        op = self._create_operation(
                            item_path, operation, output_directory, options
                        )
                        if op:
                            operations.append(op)
        
        return operations
    
    def process_operations(
        self,
        operations: List[BatchOperation],
        password: Optional[Union[str, bytes]] = None
    ) -> List[BatchResult]:
        """
        Process a list of batch operations.
        
        Args:
            operations: List of operations to process
            password: Password for encryption/decryption
            
        Returns:
            List of batch results
        """
        self.results = []
        
        if not operations:
            return self.results
        
        # Process operations in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all operations
            future_to_operation = {
                executor.submit(self._process_single_operation, op, password): op
                for op in operations
            }
            
            # Collect results
            completed = 0
            total = len(operations)
            
            for future in as_completed(future_to_operation):
                operation = future_to_operation[future]
                
                try:
                    result = future.result()
                    with self._lock:
                        self.results.append(result)
                except Exception as e:
                    result = BatchResult(
                        operation=operation,
                        success=False,
                        error_message=str(e)
                    )
                    with self._lock:
                        self.results.append(result)
                    
                    if not self.continue_on_error:
                        # Cancel remaining operations
                        for f in future_to_operation:
                            f.cancel()
                        break
                
                completed += 1
                
                # Update progress
                if self.progress_callback:
                    self.progress_callback(completed, total, result)
        
        return self.results
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of batch processing results.
        
        Returns:
            Dictionary with summary statistics
        """
        if not self.results:
            return {
                'total_operations': 0,
                'successful': 0,
                'failed': 0,
                'total_time': 0,
                'total_input_size': 0,
                'total_output_size': 0
            }
        
        successful = sum(1 for r in self.results if r.success)
        failed = len(self.results) - successful
        total_time = sum(r.duration or 0 for r in self.results)
        total_input_size = sum(r.input_size or 0 for r in self.results)
        total_output_size = sum(r.output_size or 0 for r in self.results)
        
        return {
            'total_operations': len(self.results),
            'successful': successful,
            'failed': failed,
            'success_rate': successful / len(self.results) * 100,
            'total_time': total_time,
            'average_time': total_time / len(self.results),
            'total_input_size': total_input_size,
            'total_output_size': total_output_size,
            'compression_ratio': total_output_size / total_input_size if total_input_size > 0 else 0
        }
    
    def get_failed_operations(self) -> List[BatchResult]:
        """Get list of failed operations."""
        return [r for r in self.results if not r.success]
    
    def get_successful_operations(self) -> List[BatchResult]:
        """Get list of successful operations."""
        return [r for r in self.results if r.success]
    
    def _should_process_file(
        self,
        file_path: str,
        include_patterns: Optional[List[str]],
        exclude_patterns: Optional[List[str]]
    ) -> bool:
        """Check if file should be processed based on patterns."""
        filename = os.path.basename(file_path)
        
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
    
    def _create_operation(
        self,
        input_path: str,
        operation: str,
        output_directory: Optional[str],
        options: Dict[str, Any]
    ) -> Optional[BatchOperation]:
        """Create a batch operation for a file."""
        try:
            # Determine output path
            if output_directory:
                # Create relative path structure
                rel_path = os.path.relpath(input_path, os.path.dirname(input_path))
                output_path = os.path.join(output_directory, rel_path)
            else:
                output_path = input_path
            
            # Add appropriate extension
            if operation == 'encrypt':
                output_path += '.enc'
            
            # Create output directory if needed
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            return BatchOperation(
                input_path=input_path,
                output_path=output_path,
                operation=operation,
                options=options
            )
            
        except Exception:
            return None
    
    def _process_single_operation(
        self,
        operation: BatchOperation,
        password: Optional[Union[str, bytes]]
    ) -> BatchResult:
        """Process a single batch operation."""
        start_time = time.time()
        result = BatchResult(operation=operation, success=False, start_time=start_time)

        try:
            # Get input file size
            if os.path.exists(operation.input_path):
                result.input_size = os.path.getsize(operation.input_path)

            # Perform operation
            if operation.operation == 'encrypt':
                self._encrypt_file(operation, password)
            elif operation.operation == 'decrypt':
                self._decrypt_file(operation, password)
            else:
                raise BatchProcessorError(f"Unknown operation: {operation.operation}")

            # Get output file size
            if os.path.exists(operation.output_path):
                result.output_size = os.path.getsize(operation.output_path)

            result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.end_time = time.time()
        return result
    
    def _encrypt_file(self, operation: BatchOperation, password: Union[str, bytes]) -> None:
        """Encrypt a file."""
        options = operation.options

        encrypt_file(
            operation.input_path,
            operation.output_path,
            password,
            iterations=options.get('iterations', 200000),
            hash_algorithm=options.get('hash_algorithm', 'sha256'),
            buffer_size=options.get('buffer_size', 65536)
        )
    
    def _decrypt_file(self, operation: BatchOperation, password: Union[str, bytes]) -> None:
        """Decrypt a file."""
        options = operation.options

        decrypt_file(
            operation.input_path,
            operation.output_path,
            password,
            iterations=options.get('iterations', 200000),
            hash_algorithm=options.get('hash_algorithm', 'sha256'),
            buffer_size=options.get('buffer_size', 65536)
        )
    



def create_batch_operations_from_list(
    file_list: List[str],
    operation: str,
    output_directory: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None
) -> List[BatchOperation]:
    """
    Create batch operations from a list of files.
    
    Args:
        file_list: List of file paths
        operation: Operation to perform
        output_directory: Output directory
        options: Operation options
        
    Returns:
        List of batch operations
    """
    operations = []
    options = options or {}
    
    for file_path in file_list:
        if not os.path.exists(file_path):
            continue
        
        if not os.path.isfile(file_path):
            continue
        
        # Determine output path
        if output_directory:
            filename = os.path.basename(file_path)
            output_path = os.path.join(output_directory, filename)
        else:
            output_path = file_path
        
        # Add extension
        if operation == 'encrypt':
            output_path += '.enc'
        
        # Create output directory
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        operations.append(BatchOperation(
            input_path=file_path,
            output_path=output_path,
            operation=operation,
            options=options
        ))
    
    return operations


def estimate_batch_time(
    operations: List[BatchOperation],
    file_sizes: Optional[Dict[str, int]] = None
) -> float:
    """
    Estimate time required for batch operations.
    
    Args:
        operations: List of operations
        file_sizes: Dictionary of file sizes
        
    Returns:
        Estimated time in seconds
    """
    if not operations:
        return 0.0
    
    # Rough estimates (very approximate)
    # These will vary greatly by hardware and file types
    
    total_size = 0
    for op in operations:
        if file_sizes and op.input_path in file_sizes:
            size = file_sizes[op.input_path]
        elif os.path.exists(op.input_path):
            size = os.path.getsize(op.input_path)
        else:
            size = 0
        
        total_size += size
    
    # Processing speed estimates (bytes per second)
    speed_estimates = {
        'encrypt': 30 * 1024 * 1024,  # 30 MB/s
        'decrypt': 40 * 1024 * 1024,  # 40 MB/s
        'compress': 50 * 1024 * 1024,  # 50 MB/s
        'decompress': 80 * 1024 * 1024,  # 80 MB/s
    }
    
    # Calculate total time
    total_time = 0.0
    for op in operations:
        if file_sizes and op.input_path in file_sizes:
            size = file_sizes[op.input_path]
        elif os.path.exists(op.input_path):
            size = os.path.getsize(op.input_path)
        else:
            size = 0
        
        speed = speed_estimates.get(op.operation, 30 * 1024 * 1024)
        total_time += size / speed
    
    return total_time


def create_progress_callback(verbose: bool = True) -> Callable:
    """
    Create a progress callback function.
    
    Args:
        verbose: Whether to show verbose output
        
    Returns:
        Progress callback function
    """
    def callback(completed: int, total: int, result: Optional[BatchResult] = None):
        if verbose:
            percentage = (completed / total) * 100
            status = "✓" if result and result.success else "✗"
            print(f"\rProgress: {completed}/{total} ({percentage:.1f}%) {status}", end='', flush=True)
            
            if completed == total:
                print()  # New line when complete
    
    return callback