"""
Command Line Interface Module

Comprehensive CLI for secure-files-cli with all commands and features.
Uses argparse for command parsing and provides rich user experience.
"""

import sys
import os
import argparse
import getpass
from typing import Optional, List, Dict, Any

from .core import encrypt_file, decrypt_file, encrypt_data, decrypt_data, EncryptionError, DecryptionError
from .key_derivation import derive_key, generate_salt, validate_password_strength
from .key_management import generate_keyfile, load_keyfile, verify_keyfile, rotate_keyfile, list_keyfiles
from .config import Config, load_config, create_default_config, ensure_config_directories
# from .compression import compress_file, decompress_file, list_compression_algorithms, detect_compression_algorithm
from .batch_processor import BatchProcessor, create_batch_operations_from_list, create_progress_callback
from .integrity import get_file_hash, create_checksum_file, verify_checksum_file, create_integrity_manifest
from .secure_delete import secure_delete_file, get_available_methods
from .utils import (
    format_file_size, format_duration, create_progress_bar, print_error, print_success, print_warning,
    confirm_action, create_table, validate_file_path, validate_directory_path, get_system_info
)


class CLIError(Exception):
    """Raised when CLI operations fail."""
    pass


class SecureFilesCLI:
    """Main CLI application class."""
    
    def __init__(self):
        """Initialize CLI application."""
        self.config: Optional[Config] = None
        self.verbose = False
        self.use_rich = True
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the CLI application.
        
        Args:
            args: Command line arguments (default: sys.argv)
            
        Returns:
            Exit code
        """
        try:
            parser = self._create_parser()
            parsed_args = parser.parse_args(args)
            
            # Load configuration
            self._load_configuration(parsed_args)
            
            # Set verbosity
            self.verbose = parsed_args.verbose
            self.use_rich = not parsed_args.no_rich
            
            # Execute command
            return parsed_args.func(parsed_args)
            
        except KeyboardInterrupt:
            print_error("Operation cancelled by user", self.use_rich)
            return 1
        except CLIError as e:
            print_error(str(e), self.use_rich)
            return 1
        except Exception as e:
            if self.verbose:
                import traceback
                traceback.print_exc()
            else:
                print_error(f"Unexpected error: {e}", self.use_rich)
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser."""
        parser = argparse.ArgumentParser(
            prog='secure-files-cli',
            description='Advanced file encryption tool with AES-256-GCM',
            epilog='For more information, visit: https://github.com/Eternal0404/secure-files-cli',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Global options
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('--no-rich', action='store_true', help='Disable rich formatting')
        parser.add_argument('--config', help='Configuration file path')
        parser.add_argument('--profile', help='Configuration profile to use')
        parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
        
        # Create subparsers
        subparsers = parser.add_subparsers(dest='command', title='Commands', metavar='COMMAND')
        
        # Encrypt command
        encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
        encrypt_parser.add_argument('input', help='Input file to encrypt')
        encrypt_parser.add_argument('-o', '--output', help='Output encrypted file')
        encrypt_parser.add_argument('-p', '--password', help='Encryption password')
        encrypt_parser.add_argument('--keyfile', help='Keyfile for encryption')
        encrypt_parser.add_argument('--compress', action='store_true', help='Compress before encryption')
        encrypt_parser.add_argument('--compression-algorithm', default='gzip', help='Compression algorithm')
        encrypt_parser.add_argument('--compression-level', type=int, default=6, help='Compression level (1-9)')
        encrypt_parser.add_argument('--iterations', type=int, help='PBKDF2 iterations')
        encrypt_parser.add_argument('--hash-algorithm', default='sha256', help='Hash algorithm')
        encrypt_parser.add_argument('--backup', action='store_true', help='Create backup of original file')
        encrypt_parser.add_argument('--shred', action='store_true', help='Securely delete original file')
        encrypt_parser.add_argument('--shred-passes', type=int, default=3, help='Secure delete passes')
        encrypt_parser.set_defaults(func=self._cmd_encrypt)
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
        decrypt_parser.add_argument('input', help='Input encrypted file')
        decrypt_parser.add_argument('-o', '--output', help='Output decrypted file')
        decrypt_parser.add_argument('-p', '--password', help='Decryption password')
        decrypt_parser.add_argument('--keyfile', help='Keyfile for decryption')
        decrypt_parser.add_argument('--decompress', action='store_true', help='Decompress after decryption')
        decrypt_parser.add_argument('--iterations', type=int, help='PBKDF2 iterations')
        decrypt_parser.add_argument('--hash-algorithm', default='sha256', help='Hash algorithm')
        decrypt_parser.add_argument('--verify', action='store_true', help='Verify file integrity')
        decrypt_parser.set_defaults(func=self._cmd_decrypt)
        
        # Batch command
        batch_parser = subparsers.add_parser('batch', help='Batch operations')
        batch_subparsers = batch_parser.add_subparsers(dest='batch_command', title='Batch Commands')
        
        # Batch encrypt
        batch_encrypt_parser = batch_subparsers.add_parser('encrypt', help='Batch encrypt files')
        batch_encrypt_parser.add_argument('input', help='Input directory or file list')
        batch_encrypt_parser.add_argument('-o', '--output', help='Output directory')
        batch_encrypt_parser.add_argument('-p', '--password', help='Encryption password')
        batch_encrypt_parser.add_argument('--keyfile', help='Keyfile for encryption')
        batch_encrypt_parser.add_argument('--compress', action='store_true', help='Compress before encryption')
        batch_encrypt_parser.add_argument('--recursive', action='store_true', help='Process directories recursively')
        batch_encrypt_parser.add_argument('--include', nargs='+', help='Include patterns')
        batch_encrypt_parser.add_argument('--exclude', nargs='+', help='Exclude patterns')
        batch_encrypt_parser.add_argument('--max-workers', type=int, default=4, help='Maximum parallel workers')
        batch_encrypt_parser.add_argument('--continue-on-error', action='store_true', help='Continue on errors')
        batch_encrypt_parser.set_defaults(func=self._cmd_batch_encrypt)
        
        # Batch decrypt
        batch_decrypt_parser = batch_subparsers.add_parser('decrypt', help='Batch decrypt files')
        batch_decrypt_parser.add_argument('input', help='Input directory or file list')
        batch_decrypt_parser.add_argument('-o', '--output', help='Output directory')
        batch_decrypt_parser.add_argument('-p', '--password', help='Decryption password')
        batch_decrypt_parser.add_argument('--keyfile', help='Keyfile for decryption')
        batch_decrypt_parser.add_argument('--decompress', action='store_true', help='Decompress after decryption')
        batch_decrypt_parser.add_argument('--recursive', action='store_true', help='Process directories recursively')
        batch_decrypt_parser.add_argument('--max-workers', type=int, default=4, help='Maximum parallel workers')
        batch_decrypt_parser.add_argument('--continue-on-error', action='store_true', help='Continue on errors')
        batch_decrypt_parser.set_defaults(func=self._cmd_batch_decrypt)
        
        # Key management commands
        key_parser = subparsers.add_parser('key', help='Key management')
        key_subparsers = key_parser.add_subparsers(dest='key_command', title='Key Commands')
        
        # Generate keyfile
        keygen_parser = key_subparsers.add_parser('generate', help='Generate a keyfile')
        keygen_parser.add_argument('output', help='Output keyfile path')
        keygen_parser.add_argument('--encrypt', action='store_true', help='Encrypt the keyfile')
        keygen_parser.add_argument('--algorithm', default='AES-256', help='Key algorithm')
        keygen_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing keyfile')
        keygen_parser.set_defaults(func=self._cmd_key_generate)
        
        # List keyfiles
        keylist_parser = key_subparsers.add_parser('list', help='List keyfiles')
        keylist_parser.add_argument('directory', nargs='?', help='Directory to search')
        keylist_parser.set_defaults(func=self._cmd_key_list)
        
        # Verify keyfile
        keyverify_parser = key_subparsers.add_parser('verify', help='Verify a keyfile')
        keyverify_parser.add_argument('keyfile', help='Keyfile to verify')
        keyverify_parser.add_argument('-p', '--password', help='Keyfile password')
        keyverify_parser.set_defaults(func=self._cmd_key_verify)
        
        # Rotate keyfile
        keyrotate_parser = key_subparsers.add_parser('rotate', help='Rotate a keyfile')
        keyrotate_parser.add_argument('old_keyfile', help='Old keyfile')
        keyrotate_parser.add_argument('new_keyfile', help='New keyfile')
        keyrotate_parser.add_argument('--old-password', help='Old keyfile password')
        keyrotate_parser.add_argument('--new-password', help='New keyfile password')
        keyrotate_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing keyfile')
        keyrotate_parser.set_defaults(func=self._cmd_key_rotate)
        
        # Compression commands
        compress_parser = subparsers.add_parser('compress', help='Compression operations')
        compress_subparsers = compress_parser.add_subparsers(dest='compress_command', title='Compression Commands')
        
        # Compress file
        comp_file_parser = compress_subparsers.add_parser('file', help='Compress a file')
        comp_file_parser.add_argument('input', help='Input file')
        comp_file_parser.add_argument('-o', '--output', help='Output file')
        comp_file_parser.add_argument('--algorithm', default='gzip', help='Compression algorithm')
        comp_file_parser.add_argument('--level', type=int, default=6, help='Compression level')
        comp_file_parser.set_defaults(func=self._cmd_compress_file)
        
        # Decompress file
        decomp_file_parser = compress_subparsers.add_parser('decompress', help='Decompress a file')
        decomp_file_parser.add_argument('input', help='Input file')
        decomp_file_parser.add_argument('-o', '--output', help='Output file')
        decomp_file_parser.add_argument('--algorithm', help='Compression algorithm (auto-detect if not specified)')
        decomp_file_parser.set_defaults(func=self._cmd_decompress_file)
        
        # List algorithms
        comp_list_parser = compress_subparsers.add_parser('list', help='List compression algorithms')
        comp_list_parser.set_defaults(func=self._cmd_compress_list)
        
        # Integrity commands
        integrity_parser = subparsers.add_parser('integrity', help='File integrity operations')
        integrity_subparsers = integrity_parser.add_subparsers(dest='integrity_command', title='Integrity Commands')
        
        # Create checksums
        checksum_parser = integrity_subparsers.add_parser('checksum', help='Create checksum file')
        checksum_parser.add_argument('directory', help='Directory to scan')
        checksum_parser.add_argument('--algorithm', default='sha256', help='Hash algorithm')
        checksum_parser.add_argument('--output', default='CHECKSUMS', help='Output filename')
        checksum_parser.add_argument('--recursive', action='store_true', help='Scan recursively')
        checksum_parser.add_argument('--include', nargs='+', help='Include patterns')
        checksum_parser.add_argument('--exclude', nargs='+', help='Exclude patterns')
        checksum_parser.set_defaults(func=self._cmd_integrity_checksum)
        
        # Verify checksums
        verify_parser = integrity_subparsers.add_parser('verify', help='Verify checksum file')
        verify_parser.add_argument('checksum_file', help='Checksum file to verify')
        verify_parser.add_argument('--directory', help='Base directory (default: same as checksum file)')
        verify_parser.add_argument('--algorithm', default='sha256', help='Hash algorithm')
        verify_parser.set_defaults(func=self._cmd_integrity_verify)
        
        # Create manifest
        manifest_parser = integrity_subparsers.add_parser('manifest', help='Create integrity manifest')
        manifest_parser.add_argument('directory', help='Directory to scan')
        manifest_parser.add_argument('--algorithm', default='sha256', help='Hash algorithm')
        manifest_parser.add_argument('--output', default='MANIFEST.json', help='Output filename')
        manifest_parser.add_argument('--recursive', action='store_true', help='Scan recursively')
        manifest_parser.add_argument('--metadata', action='store_true', help='Include file metadata')
        manifest_parser.set_defaults(func=self._cmd_integrity_manifest)
        
        # Secure delete commands
        shred_parser = subparsers.add_parser('shred', help='Secure file deletion')
        shred_parser.add_argument('file', help='File to securely delete')
        shred_parser.add_argument('--passes', type=int, default=3, help='Number of overwrite passes')
        shred_parser.add_argument('--method', default='random', help='Deletion method')
        shred_parser.add_argument('--verify', action='store_true', help='Verify deletion')
        shred_parser.add_argument('--confirm', action='store_true', help='Ask for confirmation')
        shred_parser.set_defaults(func=self._cmd_shred)
        
        # Configuration commands
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_subparsers = config_parser.add_subparsers(dest='config_command', title='Config Commands')
        
        # Show config
        config_show_parser = config_subparsers.add_parser('show', help='Show current configuration')
        config_show_parser.set_defaults(func=self._cmd_config_show)
        
        # Create default config
        config_create_parser = config_subparsers.add_parser('create', help='Create default configuration')
        config_create_parser.add_argument('file', help='Configuration file path')
        config_create_parser.set_defaults(func=self._cmd_config_create)
        
        # Set config value
        config_set_parser = config_subparsers.add_parser('set', help='Set configuration value')
        config_set_parser.add_argument('key', help='Configuration key')
        config_set_parser.add_argument('value', help='Configuration value')
        config_set_parser.set_defaults(func=self._cmd_config_set)
        
        # Info commands
        info_parser = subparsers.add_parser('info', help='Show system information')
        info_parser.set_defaults(func=self._cmd_info)
        
        return parser
    
    def _load_configuration(self, args: argparse.Namespace) -> None:
        """Load configuration from file or defaults."""
        try:
            self.config = load_config(args.config, args.profile)
        except Exception as e:
            if self.verbose:
                print_warning(f"Failed to load configuration: {e}", self.use_rich)
            self.config = Config()
    
    def _get_password(self, args: argparse.Namespace, confirm: bool = False) -> str:
        """Get password from args or prompt."""
        if args.password:
            return args.password
        
        try:
            password = getpass.getpass("Enter password: ")
            if confirm:
                confirm_password = getpass.getpass("Confirm password: ")
                if password != confirm_password:
                    raise CLIError("Passwords do not match")
            
            # Validate password strength
            strength_info = validate_password_strength(password)
            if strength_info['strength'] == 'weak':
                print_warning("Weak password detected. Consider using a stronger password.", self.use_rich)
            
            return password
        except KeyboardInterrupt:
            raise CLIError("Password input cancelled")
    
    def _cmd_encrypt(self, args: argparse.Namespace) -> int:
        """Handle encrypt command."""
        # Validate input file
        if not validate_file_path(args.input, must_exist=True):
            raise CLIError(f"Invalid input file: {args.input}")
        
        # Determine output file
        if args.output:
            output_path = args.output
        else:
            output_path = args.input + ".enc"
        
        # Validate output path
        if not validate_file_path(output_path, must_exist=False):
            raise CLIError(f"Invalid output file: {args.output}")
        
        # Get password
        password = self._get_password(args, confirm=True)
        
        # Create backup if requested
        if args.backup:
            backup_path = None
            try:
                from .utils import create_backup
                backup_path = create_backup(args.input)
                print_success(f"Backup created: {backup_path}", self.use_rich)
            except Exception as e:
                print_warning(f"Failed to create backup: {e}", self.use_rich)
        
        # Get encryption options
        iterations = getattr(args, 'iterations', None) or (self.config.get('encryption.iterations', 200000) if self.config else 200000)
        hash_algorithm = getattr(args, 'hash_algorithm', None) or (self.config.get('encryption.hash_algorithm', 'sha256') if self.config else 'sha256')
        buffer_size = self.config.get('encryption.buffer_size', 65536) if self.config else 65536
        
        # Create progress bar
        file_size = os.path.getsize(args.input)
        progress_bar = create_progress_bar(file_size, "Encrypting", self.use_rich)
        
        def progress_callback(bytes_processed, total_bytes):
            if hasattr(progress_bar, 'update'):
                progress_bar.update(bytes_processed - progress_bar.n)
            elif hasattr(progress_bar, 'set_progress'):
                progress_bar.set_progress(bytes_processed / total_bytes)
        
        try:
            # Encrypt file
            encrypt_file(
                args.input,
                output_path,
                password,
                iterations=iterations,
                hash_algorithm=hash_algorithm,
                buffer_size=buffer_size,
                progress_callback=progress_callback if self.verbose else None
            )
            
            print_success(f"File encrypted successfully: {output_path}", self.use_rich)
            
            # Show file info
            if self.verbose:
                original_size = os.path.getsize(args.input)
                encrypted_size = os.path.getsize(output_path)
                compression_ratio = encrypted_size / original_size
                
                print(f"Original size: {format_file_size(original_size)}")
                print(f"Encrypted size: {format_file_size(encrypted_size)}")
                print(f"Size increase: {compression_ratio:.2f}x")
            
            # Secure delete original if requested
            if args.shred:
                if args.confirm and not confirm_action("Securely delete original file?"):
                    print_warning("Original file preserved", self.use_rich)
                else:
                    secure_delete_file(args.input, passes=args.shred_passes)
                    print_success("Original file securely deleted", self.use_rich)
            
            return 0
            
        except EncryptionError as e:
            raise CLIError(f"Encryption failed: {e}")
        finally:
            if hasattr(progress_bar, 'close'):
                progress_bar.close()
    
    def _cmd_decrypt(self, args: argparse.Namespace) -> int:
        """Handle decrypt command."""
        # Validate input file
        if not validate_file_path(args.input, must_exist=True):
            raise CLIError(f"Invalid input file: {args.input}")
        
        # Determine output file
        if args.output:
            output_path = args.output
        else:
            if args.input.endswith('.enc'):
                output_path = args.input[:-4]
            else:
                output_path = args.input + ".dec"
        
        # Validate output path
        if not validate_file_path(output_path, must_exist=False):
            raise CLIError(f"Invalid output file: {args.output}")
        
        # Get password
        password = self._get_password(args)
        
        # Get decryption options
        iterations = getattr(args, 'iterations', None) or (self.config.get('encryption.iterations', 200000) if self.config else 200000)
        hash_algorithm = getattr(args, 'hash_algorithm', None) or (self.config.get('encryption.hash_algorithm', 'sha256') if self.config else 'sha256')
        buffer_size = self.config.get('encryption.buffer_size', 65536) if self.config else 65536
        
        # Create progress bar
        file_size = os.path.getsize(args.input)
        progress_bar = create_progress_bar(file_size, "Decrypting", self.use_rich)
        
        def progress_callback(bytes_processed, total_bytes):
            if hasattr(progress_bar, 'update'):
                progress_bar.update(bytes_processed - progress_bar.n)
            elif hasattr(progress_bar, 'set_progress'):
                progress_bar.set_progress(bytes_processed / total_bytes)
        
        try:
            # Decrypt file
            decrypt_file(
                args.input,
                output_path,
                password,
                iterations=iterations,
                hash_algorithm=hash_algorithm,
                buffer_size=buffer_size,
                progress_callback=progress_callback if self.verbose else None
            )
            
            print_success(f"File decrypted successfully: {output_path}", self.use_rich)
            
            # Verify integrity if requested
            if args.verify:
                try:
                    original_hash = get_file_hash(args.input)
                    decrypted_hash = get_file_hash(output_path)
                    
                    if original_hash == decrypted_hash:
                        print_success("File integrity verified", self.use_rich)
                    else:
                        print_warning("File integrity check failed", self.use_rich)
                except Exception as e:
                    print_warning(f"Failed to verify integrity: {e}", self.use_rich)
            
            # Show file info
            if self.verbose:
                encrypted_size = os.path.getsize(args.input)
                decrypted_size = os.path.getsize(output_path)
                
                print(f"Encrypted size: {format_file_size(encrypted_size)}")
                print(f"Decrypted size: {format_file_size(decrypted_size)}")
            
            return 0
            
        except DecryptionError as e:
            raise CLIError(f"Decryption failed: {e}")
        finally:
            if hasattr(progress_bar, 'close'):
                progress_bar.close()
    
    def _cmd_batch_encrypt(self, args: argparse.Namespace) -> int:
        """Handle batch encrypt command."""
        return self._process_batch_command(args, 'encrypt')
    
    def _cmd_batch_decrypt(self, args: argparse.Namespace) -> int:
        """Handle batch decrypt command."""
        return self._process_batch_command(args, 'decrypt')
    
    def _process_batch_command(self, args: argparse.Namespace, operation: str) -> int:
        """Process batch encryption/decryption command."""
        # Get password
        password = self._get_password(args, confirm=(operation == 'encrypt'))
        
        # Create batch processor
        max_workers = getattr(args, 'max_workers', None) or (self.config.get('batch_processing.max_workers', 4) if self.config else 4)
        continue_on_error = getattr(args, 'continue_on_error', None) or (self.config.get('batch_processing.continue_on_error', False) if self.config else False)
        
        progress_callback = create_progress_callback(self.verbose) if self.verbose else None
        
        processor = BatchProcessor(
            max_workers=max_workers,
            continue_on_error=continue_on_error,
            progress_callback=progress_callback
        )
        
        try:
            # Scan for operations
            if os.path.isdir(args.input):
                operations = processor.scan_directory(
                    args.input,
                    operation,
                    args.output,
                    include_patterns=getattr(args, 'include', None),
                    exclude_patterns=getattr(args, 'exclude', None),
                    recursive=getattr(args, 'recursive', False),
                    options=self._get_batch_options(args, operation)
                )
            else:
                # Treat as file list
                with open(args.input, 'r') as f:
                    file_list = [line.strip() for line in f if line.strip()]
                
                operations = create_batch_operations_from_list(
                    file_list,
                    operation,
                    args.output,
                    self._get_batch_options(args, operation)
                )
            
            if not operations:
                print_warning("No files found to process", self.use_rich)
                return 0
            
            print(f"Found {len(operations)} files to {operation}")
            
            # Process operations
            results = processor.process_operations(operations, password)
            
            # Show summary
            summary = processor.get_summary()
            
            print(f"\nBatch {operation} completed:")
            print(f"  Total operations: {summary['total_operations']}")
            print(f"  Successful: {summary['successful']}")
            print(f"  Failed: {summary['failed']}")
            print(f"  Success rate: {summary['success_rate']:.1f}%")
            print(f"  Total time: {format_duration(summary['total_time'])}")
            
            if summary['total_input_size'] > 0:
                print(f"  Total input: {format_file_size(summary['total_input_size'])}")
                print(f"  Total output: {format_file_size(summary['total_output_size'])}")
            
            # Show failed operations if any
            failed_ops = processor.get_failed_operations()
            if failed_ops and self.verbose:
                print(f"\nFailed operations:")
                for result in failed_ops:
                    print(f"  {result.operation.input_path}: {result.error_message}")
            
            return 0 if summary['failed'] == 0 else 1
            
        except Exception as e:
            raise CLIError(f"Batch {operation} failed: {e}")
    
    def _get_batch_options(self, args: argparse.Namespace, operation: str) -> Dict[str, Any]:
        """Get batch operation options."""
        options = {}
        
        if operation == 'encrypt':
            options.update({
                'compress': getattr(args, 'compress', False),
                'compression_algorithm': getattr(args, 'compression_algorithm', 'gzip'),
                'compression_level': getattr(args, 'compression_level', 6),
                'iterations': getattr(args, 'iterations', None) or (self.config.get('encryption.iterations', 200000) if self.config else 200000),
                'hash_algorithm': getattr(args, 'hash_algorithm', None) or (self.config.get('encryption.hash_algorithm', 'sha256') if self.config else 'sha256'),
                'buffer_size': self.config.get('encryption.buffer_size', 65536) if self.config else 65536
            })
        elif operation == 'decrypt':
            options.update({
                'decompress': getattr(args, 'decompress', False),
                'iterations': getattr(args, 'iterations', None) or (self.config.get('encryption.iterations', 200000) if self.config else 200000),
                'hash_algorithm': getattr(args, 'hash_algorithm', None) or (self.config.get('encryption.hash_algorithm', 'sha256') if self.config else 'sha256'),
                'buffer_size': self.config.get('encryption.buffer_size', 65536) if self.config else 65536
            })
        
        return options
    
    def _cmd_key_generate(self, args: argparse.Namespace) -> int:
        """Handle keyfile generation command."""
        try:
            # Generate keyfile
            keyfile_path = generate_keyfile(
                args.output,
                encrypt_keyfile=args.encrypt,
                keyfile_password=getpass.getpass("Keyfile password: ") if args.encrypt else None,
                overwrite=args.overwrite
            )
            
            print_success(f"Keyfile generated: {keyfile_path}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Keyfile generation failed: {e}")
    
    def _cmd_key_list(self, args: argparse.Namespace) -> int:
        """Handle keyfile listing command."""
        try:
            directory = args.directory or self.config.get('paths.keyfile_directory', '~/.secure-files-cli/keys')
            keyfiles = list_keyfiles(directory)
            
            if not keyfiles:
                print_warning("No keyfiles found", self.use_rich)
                return 0
            
            # Create table
            headers = ['Keyfile', 'Size', 'Modified']
            rows = []
            
            for keyfile in keyfiles:
                try:
                    stat_info = os.stat(keyfile)
                    size = format_file_size(stat_info.st_size)
                    modified = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime))
                    rows.append([os.path.basename(keyfile), size, modified])
                except:
                    rows.append([os.path.basename(keyfile), 'Unknown', 'Unknown'])
            
            create_table(headers, rows, self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Failed to list keyfiles: {e}")
    
    def _cmd_key_verify(self, args: argparse.Namespace) -> int:
        """Handle keyfile verification command."""
        try:
            password = getpass.getpass("Keyfile password: ") if args.password else None
            
            is_valid = verify_keyfile(args.keyfile, password)
            
            if is_valid:
                print_success("Keyfile is valid", self.use_rich)
                return 0
            else:
                print_error("Keyfile is invalid or corrupted", self.use_rich)
                return 1
                
        except Exception as e:
            raise CLIError(f"Keyfile verification failed: {e}")
    
    def _cmd_key_rotate(self, args: argparse.Namespace) -> int:
        """Handle keyfile rotation command."""
        try:
            old_password = getpass.getpass("Old keyfile password: ") if args.old_password else None
            new_password = getpass.getpass("New keyfile password: ") if args.new_password else None
            
            new_keyfile_path = rotate_keyfile(
                args.old_keyfile,
                args.new_keyfile,
                old_password,
                new_password,
                args.overwrite
            )
            
            print_success(f"Keyfile rotated: {new_keyfile_path}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Keyfile rotation failed: {e}")
    
    def _cmd_compress_file(self, args: argparse.Namespace) -> int:
        """Handle file compression command."""
        try:
            compress_file(
                args.input,
                args.output or (args.input + '.gz'),
                algorithm=args.algorithm,
                level=args.level
            )
            
            print_success(f"File compressed: {args.output}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Compression failed: {e}")
    
    def _cmd_decompress_file(self, args: argparse.Namespace) -> int:
        """Handle file decompression command."""
        try:
            algorithm = args.algorithm or detect_compression_algorithm(args.input)
            if not algorithm:
                raise CLIError("Cannot determine compression algorithm")
            
            decompress_file(
                args.input,
                args.output,
                algorithm
            )
            
            print_success(f"File decompressed: {args.output}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Decompression failed: {e}")
    
    def _cmd_compress_list(self, args: argparse.Namespace) -> int:
        """Handle compression algorithm listing command."""
        algorithms = list_compression_algorithms()
        
        headers = ['Algorithm', 'Available']
        rows = []
        
        for algo in algorithms:
            rows.append([algo, 'Yes'])
        
        create_table(headers, rows, self.use_rich)
        return 0
    
    def _cmd_integrity_checksum(self, args: argparse.Namespace) -> int:
        """Handle checksum creation command."""
        try:
            create_checksum_file(
                args.directory,
                args.output,
                args.algorithm,
                args.recursive,
                args.include,
                args.exclude
            )
            
            print_success(f"Checksum file created: {args.output}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Checksum creation failed: {e}")
    
    def _cmd_integrity_verify(self, args: argparse.Namespace) -> int:
        """Handle checksum verification command."""
        try:
            results = verify_checksum_file(args.checksum_file, args.directory, args.algorithm)
            
            if not results:
                print_warning("No files found in checksum file", self.use_rich)
                return 0
            
            valid_count = sum(1 for r in results.values() if r)
            total_count = len(results)
            
            print(f"Verification results: {valid_count}/{total_count} files valid")
            
            if valid_count == total_count:
                print_success("All files verified successfully", self.use_rich)
                return 0
            else:
                print_warning(f"{total_count - valid_count} files failed verification", self.use_rich)
                
                if self.verbose:
                    print("\nFailed files:")
                    for file_path, is_valid in results.items():
                        if not is_valid:
                            print(f"  {file_path}")
                
                return 1
                
        except Exception as e:
            raise CLIError(f"Checksum verification failed: {e}")
    
    def _cmd_integrity_manifest(self, args: argparse.Namespace) -> int:
        """Handle manifest creation command."""
        try:
            create_integrity_manifest(
                args.directory,
                args.output,
                args.algorithm,
                args.recursive,
                args.metadata
            )
            
            print_success(f"Integrity manifest created: {args.output}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Manifest creation failed: {e}")
    
    def _cmd_shred(self, args: argparse.Namespace) -> int:
        """Handle secure delete command."""
        try:
            # Confirm deletion
            if args.confirm and not confirm_action(f"Securely delete {args.file}?"):
                print_warning("Deletion cancelled", self.use_rich)
                return 0
            
            secure_delete_file(
                args.file,
                passes=args.passes,
                verify=args.verify,
                method=args.method
            )
            
            print_success(f"File securely deleted: {args.file}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Secure delete failed: {e}")
    
    def _cmd_config_show(self, args: argparse.Namespace) -> int:
        """Handle config show command."""
        try:
            config_dict = self.config.to_dict()
            
            print("Current configuration:")
            self._print_config_dict(config_dict, "")
            return 0
            
        except Exception as e:
            raise CLIError(f"Failed to show configuration: {e}")
    
    def _cmd_config_create(self, args: argparse.Namespace) -> int:
        """Handle config create command."""
        try:
            create_default_config(args.file)
            print_success(f"Default configuration created: {args.file}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Failed to create configuration: {e}")
    
    def _cmd_config_set(self, args: argparse.Namespace) -> int:
        """Handle config set command."""
        try:
            # Convert value to appropriate type
            value = args.value
            if value.lower() in ('true', 'false'):
                value = value.lower() == 'true'
            elif value.isdigit():
                value = int(value)
            
            self.config.set(args.key, value)
            self.config.save()
            
            print_success(f"Configuration updated: {args.key} = {value}", self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Failed to set configuration: {e}")
    
    def _cmd_info(self, args: argparse.Namespace) -> int:
        """Handle info command."""
        try:
            info = get_system_info()
            
            headers = ['Property', 'Value']
            rows = []
            
            for key, value in info.items():
                if isinstance(value, (int, float)):
                    if key.endswith('_size') or key.endswith('_total'):
                        value = format_file_size(value)
                    elif key.endswith('_time'):
                        value = format_duration(value)
                
                rows.append([key.replace('_', ' ').title(), str(value)])
            
            create_table(headers, rows, self.use_rich)
            return 0
            
        except Exception as e:
            raise CLIError(f"Failed to get system info: {e}")
    
    def _print_config_dict(self, config_dict: Dict[str, Any], prefix: str = "") -> None:
        """Print configuration dictionary recursively."""
        for key, value in config_dict.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                print(f"{full_key}:")
                self._print_config_dict(value, full_key)
            else:
                print(f"  {key}: {value}")


def main() -> int:
    """Main entry point."""
    cli = SecureFilesCLI()
    return cli.run()


def main():
    """Main entry point."""
    cli = SecureFilesCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())