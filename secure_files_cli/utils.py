"""
Utilities Module

Enhanced utility functions for file operations, progress tracking,
and various helper functions used throughout the application.
"""

import os
import sys
import time
import shutil
import tempfile
import platform
import subprocess
from typing import Union, Optional, Callable, Dict, Any, BinaryIO
from pathlib import Path

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class UtilsError(Exception):
    """Raised when utility operations fail."""
    pass


def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes
        
    Raises:
        UtilsError: If file size cannot be determined
    """
    try:
        if not os.path.exists(file_path):
            raise UtilsError(f"File not found: {file_path}")
        
        return os.path.getsize(file_path)
        
    except OSError as e:
        raise UtilsError(f"Failed to get file size for {file_path}: {e}")


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    
    return f"{size:.1f} {size_names[i]}"


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds*1000:.0f} ms"
    elif seconds < 60:
        return f"{seconds:.1f} s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} min"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} h"


def create_progress_bar(
    total: int,
    description: str = "Processing",
    use_rich: bool = True,
    use_tqdm: bool = True
) -> Any:
    """
    Create a progress bar based on available libraries.
    
    Args:
        total: Total number of items
        description: Progress description
        use_rich: Prefer rich progress bar
        use_tqdm: Prefer tqdm progress bar
        
    Returns:
        Progress bar object
    """
    if use_rich and RICH_AVAILABLE:
        console = Console()
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        )
        task_id = progress.add_task(description, total=total)
        return progress, task_id
    
    elif use_tqdm and TQDM_AVAILABLE:
        return tqdm(total=total, desc=description, unit="items")
    
    else:
        # Fallback to simple text progress
        return SimpleProgressBar(total, description)


class SimpleProgressBar:
    """Simple text progress bar fallback."""
    
    def __init__(self, total: int, description: str):
        self.total = total
        self.description = description
        self.current = 0
        self.start_time = time.time()
    
    def update(self, n: int = 1):
        """Update progress by n items."""
        self.current += n
        percentage = (self.current / self.total) * 100
        elapsed = time.time() - self.start_time
        
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = format_duration(eta)
        else:
            eta_str = "unknown"
        
        print(f"\r{self.description}: {self.current}/{self.total} ({percentage:.1f}%) ETA: {eta_str}", end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete
    
    def close(self):
        """Close progress bar."""
        if self.current < self.total:
            self.update(self.total - self.current)


def secure_delete_file(file_path: str, passes: int = 3, verify: bool = True) -> None:
    """
    Securely delete a file (wrapper for secure_delete module).
    
    Args:
        file_path: Path to file
        passes: Number of overwrite passes
        verify: Whether to verify deletion
    """
    from .secure_delete import secure_delete_file as _secure_delete_file
    
    _secure_delete_file(file_path, passes, verify)


def get_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Get file hash (wrapper for integrity module).
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm
        
    Returns:
        Hexadecimal hash string
    """
    from .integrity import get_file_hash as _get_file_hash
    
    return _get_file_hash(file_path, algorithm)


def create_backup(file_path: str, backup_dir: Optional[str] = None) -> str:
    """
    Create a backup of a file.
    
    Args:
        file_path: Path to file to backup
        backup_dir: Directory for backup (default: same directory)
        
    Returns:
        Path to backup file
        
    Raises:
        UtilsError: If backup fails
    """
    try:
        if not os.path.exists(file_path):
            raise UtilsError(f"File not found: {file_path}")
        
        if backup_dir is None:
            backup_dir = os.path.dirname(file_path)
        
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate backup filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        name, ext = os.path.splitext(filename)
        backup_filename = f"{name}_backup_{timestamp}{ext}"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Copy file
        shutil.copy2(file_path, backup_path)
        
        return backup_path
        
    except Exception as e:
        raise UtilsError(f"Failed to create backup: {e}")


def ensure_directory(directory: str) -> None:
    """
    Ensure directory exists, create if necessary.
    
    Args:
        directory: Directory path
    """
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as e:
        raise UtilsError(f"Failed to create directory {directory}: {e}")


def get_temp_directory() -> str:
    """
    Get application-specific temporary directory.
    
    Returns:
        Path to temporary directory
    """
    temp_dir = tempfile.gettempdir()
    app_temp_dir = os.path.join(temp_dir, 'secure-files-cli')
    
    try:
        os.makedirs(app_temp_dir, exist_ok=True)
        
        # Set secure permissions if possible
        try:
            os.chmod(app_temp_dir, 0o700)
        except:
            pass
        
        return app_temp_dir
        
    except OSError:
        # Fallback to system temp
        return temp_dir


def clean_temp_files() -> int:
    """
    Clean temporary files created by the application.
    
    Returns:
        Number of files cleaned
    """
    from .secure_delete import secure_delete_temp_files
    
    return secure_delete_temp_files(get_temp_directory())


def validate_file_path(file_path: str, must_exist: bool = True) -> bool:
    """
    Validate a file path.
    
    Args:
        file_path: Path to validate
        must_exist: Whether file must exist
        
    Returns:
        True if valid
    """
    try:
        if must_exist and not os.path.exists(file_path):
            return False
        
        if os.path.exists(file_path) and not os.path.isfile(file_path):
            return False
        
        # Check if parent directory exists or can be created
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except:
                return False
        
        return True
        
    except:
        return False


def validate_directory_path(dir_path: str, must_exist: bool = True) -> bool:
    """
    Validate a directory path.
    
    Args:
        dir_path: Path to validate
        must_exist: Whether directory must exist
        
    Returns:
        True if valid
    """
    try:
        if must_exist and not os.path.exists(dir_path):
            return False
        
        if os.path.exists(dir_path) and not os.path.isdir(dir_path):
            return False
        
        return True
        
    except:
        return False


def get_system_info() -> Dict[str, Any]:
    """
    Get system information for debugging and optimization.
    
    Returns:
        Dictionary with system information
    """
    info = {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'python_implementation': platform.python_implementation(),
    }
    
    # Get CPU info
    try:
        import psutil
        info['cpu_count'] = psutil.cpu_count()
        info['cpu_count_logical'] = psutil.cpu_count(logical=True)
        info['memory_total'] = psutil.virtual_memory().total
        info['memory_available'] = psutil.virtual_memory().available
    except ImportError:
        pass
    
    # Get disk info
    try:
        import psutil
        disk_usage = psutil.disk_usage('.')
        info['disk_total'] = disk_usage.total
        info['disk_free'] = disk_usage.free
        info['disk_used'] = disk_usage.used
    except:
        pass
    
    return info


def check_disk_space(path: str, required_bytes: int) -> bool:
    """
    Check if there's enough disk space.
    
    Args:
        path: Path to check
        required_bytes: Required bytes
        
    Returns:
        True if enough space
    """
    try:
        import psutil
        disk_usage = psutil.disk_usage(path)
        return disk_usage.free >= required_bytes
    except ImportError:
        # Fallback: try to create a temporary file
        try:
            test_file = os.path.join(path, '.space_check_tmp')
            with open(test_file, 'wb') as f:
                f.write(b'0' * min(required_bytes, 1024 * 1024))  # Test max 1MB
            os.remove(test_file)
            return True
        except:
            return False


def get_available_memory() -> int:
    """
    Get available system memory in bytes.
    
    Returns:
        Available memory in bytes
    """
    try:
        import psutil
        return psutil.virtual_memory().available
    except ImportError:
        # Conservative fallback
        return 1024 * 1024 * 1024  # 1GB


def optimize_buffer_size(file_size: int, max_buffer_size: int = 64 * 1024 * 1024) -> int:
    """
    Optimize buffer size based on file size and available memory.
    
    Args:
        file_size: Size of file to process
        max_buffer_size: Maximum buffer size
        
    Returns:
        Optimized buffer size
    """
    available_memory = get_available_memory()
    
    # Use 1% of available memory or file size, whichever is smaller
    optimal_size = min(available_memory // 100, file_size // 100)
    
    # Clamp to reasonable bounds
    min_buffer = 4 * 1024  # 4KB minimum
    optimal_size = max(min_buffer, optimal_size)
    optimal_size = min(max_buffer_size, optimal_size)
    
    # Round to nearest power of 2 for efficiency
    return 2 ** (optimal_size.bit_length() - 1)


def confirm_action(message: str, default: bool = False) -> bool:
    """
    Ask for user confirmation.
    
    Args:
        message: Confirmation message
        default: Default response
        
    Returns:
        True if user confirms
    """
    suffix = " [Y/n]" if default else " [y/N]"
    
    while True:
        response = input(f"{message}{suffix}: ").strip().lower()
        
        if not response:
            return default
        
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'")


def print_error(message: str, use_rich: bool = True) -> None:
    """
    Print error message with formatting.
    
    Args:
        message: Error message
        use_rich: Use rich formatting if available
    """
    if use_rich and RICH_AVAILABLE:
        console = Console()
        console.print(Panel(f"[red]Error: {message}[/red]", title="Error"))
    else:
        print(f"Error: {message}", file=sys.stderr)


def print_success(message: str, use_rich: bool = True) -> None:
    """
    Print success message with formatting.
    
    Args:
        message: Success message
        use_rich: Use rich formatting if available
    """
    if use_rich and RICH_AVAILABLE:
        console = Console()
        console.print(Panel(f"[green]{message}[/green]", title="Success"))
    else:
        print(f"✓ {message}")


def print_warning(message: str, use_rich: bool = True) -> None:
    """
    Print warning message with formatting.
    
    Args:
        message: Warning message
        use_rich: Use rich formatting if available
    """
    if use_rich and RICH_AVAILABLE:
        console = Console()
        console.print(Panel(f"[yellow]{message}[/yellow]", title="Warning"))
    else:
        print(f"⚠ {message}")


def create_table(headers: list, rows: list, use_rich: bool = True) -> None:
    """
    Display data in table format.
    
    Args:
        headers: Table headers
        rows: Table rows
        use_rich: Use rich formatting if available
    """
    if use_rich and RICH_AVAILABLE:
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        
        for header in headers:
            table.add_column(header)
        
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        
        console.print(table)
    else:
        # Simple text table
        # Calculate column widths
        col_widths = [len(str(header)) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_row = " | ".join(str(headers[i]).ljust(col_widths[i]) for i in range(len(headers)))
        print(header_row)
        print("-" * len(header_row))
        
        # Print rows
        for row in rows:
            row_str = " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(row)))
            print(row_str)


def run_command(
    command: list,
    capture_output: bool = True,
    check: bool = True,
    timeout: Optional[int] = None
) -> subprocess.CompletedProcess:
    """
    Run a system command.
    
    Args:
        command: Command to run (list of arguments)
        capture_output: Whether to capture output
        check: Whether to raise exception on non-zero exit
        timeout: Command timeout in seconds
        
    Returns:
        CompletedProcess object
        
    Raises:
        UtilsError: If command fails
    """
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            check=check,
            timeout=timeout
        )
        return result
        
    except subprocess.TimeoutExpired as e:
        raise UtilsError(f"Command timed out after {timeout} seconds")
    except subprocess.CalledProcessError as e:
        raise UtilsError(f"Command failed with exit code {e.returncode}: {e.stderr}")
    except Exception as e:
        raise UtilsError(f"Failed to run command: {e}")


def is_admin() -> bool:
    """
    Check if running with administrator privileges.
    
    Returns:
        True if running as admin
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False


def request_admin_privileges() -> bool:
    """
    Request administrator privileges (Windows only).
    
    Returns:
        True if privileges obtained
    """
    if platform.system() != "Windows":
        return False
    
    try:
        import ctypes
        return ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        ) > 32
    except:
        return False


def get_mime_type(file_path: str) -> str:
    """
    Get MIME type of a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        MIME type string
    """
    import mimetypes
    
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or "application/octet-stream"


def is_binary_file(file_path: str) -> bool:
    """
    Check if file is binary.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if file is binary
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except:
        return True


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for cross-platform compatibility.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Ensure it's not empty
    if not filename:
        filename = "unnamed_file"
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        max_name_len = 255 - len(ext)
        filename = name[:max_name_len] + ext
    
    return filename