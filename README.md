# Secure Files CLI

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Eternal0404/secure-files-cli)

A comprehensive, production-ready Python CLI tool for advanced file encryption using AES-256-GCM with PBKDF2 key derivation. Features include compression, batch processing, key management, integrity verification, and secure deletion.

## 🚀 Features

### 🔐 Core Encryption
- **AES-256-GCM**: Military-grade encryption with authentication
- **PBKDF2**: Secure password-based key derivation (200,000 iterations)
- **Multiple Hash Algorithms**: SHA-256, SHA-512 support
- **Streaming Encryption**: Efficient processing of large files

### 🔑 Key Management
- **Keyfile Generation**: Create cryptographic keyfiles
- **Encrypted Keyfiles**: Protect keyfiles with passwords
- **Key Rotation**: Secure key rotation and backup
- **Multiple Key Sources**: Password + keyfile combinations

### 📦 Compression Integration
- **Multiple Algorithms**: gzip, lzma, bz2, zlib
- **Pre-encryption Compression**: Optional compression before encryption
- **Smart Detection**: Automatic compression algorithm detection
- **Configurable Levels**: Adjustable compression levels

### ⚡ Batch Processing
- **Parallel Operations**: Multi-threaded encryption/decryption
- **Directory Scanning**: Recursive folder processing
- **File Filtering**: Include/exclude patterns support
- **Progress Tracking**: Real-time progress with ETA

### 🔍 Integrity & Verification
- **File Hashing**: SHA-256, SHA-1, MD5 support
- **Checksum Files**: Create and verify checksum files
- **Integrity Manifests**: Detailed file integrity reports
- **Directory Comparison**: Compare encrypted directories

### 🗑️ Secure Deletion
- **Multiple Standards**: DoD 5220.22-M, Gutmann methods
- **Configurable Passes**: Customizable overwrite passes
- **Verification**: Optional deletion verification
- **Memory Wiping**: Secure memory cleanup

### ⚙️ Configuration Management
- **TOML/YAML Support**: Flexible configuration formats
- **Profiles**: Multiple encryption profiles
- **Environment Variables**: Override settings via environment
- **Default Management**: Sensible defaults with customization

## 📦 Installation

### From PyPI (Recommended)
```bash
pip install secure-files-cli
```

### From Source
```bash
git clone https://github.com/Eternal0404/secure-files-cli.git
cd secure-files-cli
pip install -e .
```

### Development Installation
```bash
git clone https://github.com/Eternal0404/secure-files-cli.git
cd secure-files-cli
pip install -e ".[dev]"
```

## 🎯 Quick Start

### Basic Encryption
```bash
# Encrypt a file
secure-files-cli encrypt document.pdf

# Encrypt with custom output
secure-files-cli encrypt document.pdf -o encrypted_file.enc

# Encrypt with compression
secure-files-cli encrypt document.pdf --compress
```

### Basic Decryption
```bash
# Decrypt a file
secure-files-cli decrypt document.pdf.enc

# Decrypt with custom output
secure-files-cli decrypt document.pdf.enc -o document.pdf
```

### Batch Operations
```bash
# Encrypt entire directory
secure-files-cli batch encrypt /path/to/documents --recursive

# Decrypt with parallel processing
secure-files-cli batch decrypt /path/to/encrypted --max-workers 8
```

### Key Management
```bash
# Generate a keyfile
secure-files-cli key generate my_key.key

# List keyfiles
secure-files-cli key list

# Verify keyfile
secure-files-cli key verify my_key.key
```

## 📖 Detailed Usage

### Encryption Commands

#### Single File Encryption
```bash
secure-files-cli encrypt <input_file> [OPTIONS]

Options:
  -o, --output OUTPUT          Output encrypted file
  -p, --password PASSWORD      Encryption password
  --keyfile KEYFILE           Use keyfile for encryption
  --compress                  Compress before encryption
  --compression-algorithm ALG  Compression algorithm (gzip, lzma, bz2)
  --compression-level LEVEL   Compression level (1-9)
  --iterations N             PBKDF2 iterations (default: 200000)
  --hash-algorithm ALG       Hash algorithm (sha256, sha512)
  --backup                    Create backup of original file
  --shred                     Securely delete original file
  --shred-passes N           Secure delete passes (default: 3)
```

#### Examples
```bash
# Basic encryption
secure-files-cli encrypt sensitive.pdf

# With compression and backup
secure-files-cli encrypt large_file.zip --compress --backup

# With keyfile and custom settings
secure-files-cli encrypt document.pdf --keyfile my.key --iterations 500000

# Encrypt and securely delete original
secure-files-cli encrypt secret.txt --shred --shred-passes 7
```

### Decryption Commands

#### Single File Decryption
```bash
secure-files-cli decrypt <input_file> [OPTIONS]

Options:
  -o, --output OUTPUT          Output decrypted file
  -p, --password PASSWORD      Decryption password
  --keyfile KEYFILE           Use keyfile for decryption
  --decompress                Decompress after decryption
  --iterations N             PBKDF2 iterations
  --hash-algorithm ALG       Hash algorithm
  --verify                    Verify file integrity
```

#### Examples
```bash
# Basic decryption
secure-files-cli decrypt document.pdf.enc

# With decompression
secure-files-cli decrypt compressed.gz.enc --decompress

# With integrity verification
secure-files-cli decrypt important.enc --verify
```

### Batch Processing Commands

#### Batch Encryption
```bash
secure-files-cli batch encrypt <input> [OPTIONS]

Options:
  -o, --output OUTPUT          Output directory
  -p, --password PASSWORD      Encryption password
  --keyfile KEYFILE           Use keyfile for encryption
  --compress                  Compress before encryption
  --recursive                 Process directories recursively
  --include PATTERN PATTERN   Include file patterns
  --exclude PATTERN PATTERN   Exclude file patterns
  --max-workers N            Maximum parallel workers (default: 4)
  --continue-on-error         Continue processing after errors
```

#### Batch Decryption
```bash
secure-files-cli batch decrypt <input> [OPTIONS]

Options:
  -o, --output OUTPUT          Output directory
  -p, --password PASSWORD      Decryption password
  --keyfile KEYFILE           Use keyfile for decryption
  --decompress                Decompress after decryption
  --recursive                 Process directories recursively
  --max-workers N            Maximum parallel workers (default: 4)
  --continue-on-error         Continue processing after errors
```

#### Examples
```bash
# Encrypt directory with specific patterns
secure-files-cli batch encrypt ./documents --recursive --include "*.pdf" "*.docx"

# Parallel batch processing
secure-files-cli batch encrypt ./large_folder --max-workers 8 --continue-on-error

# Decrypt with decompression
secure-files-cli batch decrypt ./encrypted --decompress --recursive
```

### Key Management Commands

#### Generate Keyfile
```bash
secure-files-cli key generate <output_file> [OPTIONS]

Options:
  --encrypt                   Encrypt the keyfile
  --algorithm ALG           Key algorithm (default: AES-256)
  --overwrite               Overwrite existing keyfile
```

#### List Keyfiles
```bash
secure-files-cli key list [DIRECTORY]

Options:
  DIRECTORY                  Directory to search (default: ~/.secure-files-cli/keys)
```

#### Verify Keyfile
```bash
secure-files-cli key verify <keyfile> [OPTIONS]

Options:
  -p, --password PASSWORD      Keyfile password (if encrypted)
```

#### Rotate Keyfile
```bash
secure-files-cli key rotate <old_keyfile> <new_keyfile> [OPTIONS]

Options:
  --old-password PASSWORD     Old keyfile password
  --new-password PASSWORD     New keyfile password
  --overwrite               Overwrite existing new keyfile
```

### Compression Commands

#### Compress File
```bash
secure-files-cli compress file <input_file> [OPTIONS]

Options:
  -o, --output OUTPUT          Output compressed file
  --algorithm ALG           Compression algorithm (gzip, lzma, bz2)
  --level N                 Compression level (1-9)
```

#### Decompress File
```bash
secure-files-cli compress decompress <input_file> [OPTIONS]

Options:
  -o, --output OUTPUT          Output decompressed file
  --algorithm ALG           Compression algorithm (auto-detect if not specified)
```

#### List Algorithms
```bash
secure-files-cli compress list
```

### Integrity Commands

#### Create Checksums
```bash
secure-files-cli integrity checksum <directory> [OPTIONS]

Options:
  --algorithm ALG           Hash algorithm (sha256, sha1, md5)
  --output FILE             Output filename (default: CHECKSUMS)
  --recursive               Scan recursively
  --include PATTERN PATTERN   Include file patterns
  --exclude PATTERN PATTERN   Exclude file patterns
```

#### Verify Checksums
```bash
secure-files-cli integrity verify <checksum_file> [OPTIONS]

Options:
  --directory DIR           Base directory (default: same as checksum file)
  --algorithm ALG           Hash algorithm
```

#### Create Manifest
```bash
secure-files-cli integrity manifest <directory> [OPTIONS]

Options:
  --algorithm ALG           Hash algorithm (sha256, sha1, md5)
  --output FILE             Output filename (default: MANIFEST.json)
  --recursive               Scan recursively
  --metadata                Include file metadata
```

### Secure Deletion Commands

#### Shred File
```bash
secure-files-cli shred <file> [OPTIONS]

Options:
  --passes N               Number of overwrite passes (default: 3)
  --method METHOD           Deletion method (random, zeros, ones, dod5220, gutmann)
  --verify                  Verify deletion
  --confirm                 Ask for confirmation
```

### Configuration Commands

#### Show Configuration
```bash
secure-files-cli config show
```

#### Create Default Config
```bash
secure-files-cli config create <config_file>
```

#### Set Configuration Value
```bash
secure-files-cli config set <key> <value>

Examples:
  secure-files-cli config set encryption.iterations 500000
  secure-files-cli config set output.verbose true
  secure-files-cli config set batch_processing.max_workers 8
```

### System Information
```bash
secure-files-cli info
```

## 🔧 Configuration

### Configuration File Locations
The application searches for configuration files in the following order:
1. `./secure-files-cli.toml` (local)
2. `./secure-files-cli.yaml` (local)
3. `~/.secure-files-cli/config.toml` (user)
4. `~/.secure-files-cli/config.yaml` (user)

### Example Configuration (TOML)
```toml
[encryption]
algorithm = "AES-256-GCM"
iterations = 200000
hash_algorithm = "sha256"
buffer_size = 65536

[encryption.compression]
enabled = false
algorithm = "gzip"
level = 6

[key_management]
default_keyfile_format = "raw"
keyfile_extension = ".key"
encrypt_keyfiles = false
auto_backup = false
backup_directory = "~/.secure-files-cli/backups"

[security.secure_delete]
enabled = true
passes = 3
verify = true

[batch_processing]
max_workers = 4
chunk_size = 1048576
progress_updates = true
continue_on_error = false

[output]
verbose = false
progress_bars = true
color_output = true
log_level = "INFO"

[paths]
config_directory = "~/.secure-files-cli"
keyfile_directory = "~/.secure-files-cli/keys"
temp_directory = "~/.secure-files-cli/temp"
log_directory = "~/.secure-files-cli/logs"
```

### Environment Variables
Override configuration with environment variables:
```bash
export SECURE_FILES_CLI_ITERATIONS=500000
export SECURE_FILES_CLI_VERBOSE=true
export SECURE_FILES_CLI_MAX_WORKERS=8
export SECURE_FILES_CLI_CONFIG_DIR=/custom/config/path
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=secure_files_cli --cov-report=html

# Run specific test file
pytest tests/test_core.py

# Run with verbose output
pytest -v
```

### Test Coverage
The project includes comprehensive tests covering:
- Core encryption/decryption functionality
- Key derivation and management
- Compression algorithms
- Batch processing
- Integrity verification
- Configuration management
- Error handling and edge cases

## 🔒 Security Features

### Encryption Security
- **AES-256-GCM**: Provides confidentiality and authentication
- **Random Nonces**: Unique nonce for each encryption
- **Authentication Tags**: Verify data integrity
- **Secure Key Derivation**: PBKDF2 with high iteration count

### Memory Security
- **Key Wiping**: Secure memory cleanup after use
- **Zeroization**: Overwrite sensitive data in memory
- **Secure Temp Files**: Protected temporary file handling

### File Security
- **Atomic Operations**: Prevent partial file corruption
- **Permission Management**: Secure file permissions
- **Backup Creation**: Optional backup before overwriting

## 🚀 Performance

### Optimizations
- **Streaming Processing**: Handle files of any size efficiently
- **Parallel Operations**: Multi-threaded batch processing
- **Memory Management**: Optimized buffer sizes based on system resources
- **Progress Tracking**: Real-time progress with minimal overhead

### Benchmarks
Typical performance on modern hardware:
- **Encryption**: ~50-100 MB/s (depending on file size and system)
- **Decryption**: ~60-120 MB/s
- **Compression**: ~100-200 MB/s (gzip)
- **Batch Processing**: Scales with CPU cores (4-8 workers optimal)

## 🐛 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Ensure all dependencies are installed
pip install -r requirements.txt

# For development dependencies
pip install -e ".[dev]"
```

#### Permission Errors
```bash
# On Unix/Linux, ensure proper permissions
chmod 600 your_keyfile.key

# On Windows, run as administrator if needed
```

#### Memory Issues with Large Files
```bash
# Reduce buffer size in configuration
secure-files-cli config set encryption.buffer_size 32768

# Or use environment variable
export SECURE_FILES_CLI_BUFFER_SIZE=32768
```

#### Decryption Failures
- Verify password is correct
- Check file isn't corrupted
- Ensure correct PBKDF2 iterations
- Verify keyfile if used

### Debug Mode
Enable verbose output for debugging:
```bash
secure-files-cli --verbose encrypt file.txt
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/Eternal0404/secure-files-cli.git
cd secure-files-cli
pip install -e ".[dev]"
pre-commit install
```

### Code Style
- Use Black for formatting
- Follow PEP 8 guidelines
- Add type hints where appropriate
- Write comprehensive tests
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [PyCryptodome](https://www.pycryptodome.org/) - Cryptographic library
- [Rich](https://github.com/Textualize/rich) - Rich text and beautiful formatting
- [TQDM](https://github.com/tqdm/tqdm) - Fast, extensible progress bars
- [Click](https://github.com/pallets/click) - Composable command line interface toolkit

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/Eternal0404/secure-files-cli/wiki)
- **Issues**: [GitHub Issues](https://github.com/Eternal0404/secure-files-cli/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Eternal0404/secure-files-cli/discussions)

## 🔮 Roadmap

- [ ] GUI interface (optional)
- [ ] Cloud storage integration
- [ ] Additional compression algorithms
- [ ] Hardware security module (HSM) support
- [ ] Plugin system for custom algorithms
- [ ] Mobile app companion

---

**⚠️ Security Notice**: This tool is provided as-is. Users should verify the security of their implementations and consider additional security measures for highly sensitive data. Always keep backups of important files and test encryption/decryption workflows thoroughly.