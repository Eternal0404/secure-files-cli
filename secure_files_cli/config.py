"""
Configuration Management Module

Handles configuration loading, saving, and management using TOML and YAML formats.
Supports profiles, environment variables, and default settings.
"""

import os
import json
from typing import Any, Dict, Optional, Union
from pathlib import Path

try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ConfigError(Exception):
    """Raised when configuration operations fail."""
    pass


class Config:
    """
    Configuration manager for secure-files-cli.
    
    Supports loading from TOML/YAML files, environment variables,
    and provides sensible defaults.
    """
    
    DEFAULT_CONFIG = {
        'encryption': {
            'algorithm': 'AES-256-GCM',
            'iterations': 200000,
            'hash_algorithm': 'sha256',
            'buffer_size': 65536,
            'compression': {
                'enabled': False,
                'algorithm': 'gzip',
                'level': 6
            }
        },
        'key_management': {
            'default_keyfile_format': 'raw',
            'keyfile_extension': '.key',
            'encrypt_keyfiles': False,
            'auto_backup': False,
            'backup_directory': '~/.secure-files-cli/backups'
        },
        'security': {
            'secure_delete': {
                'enabled': True,
                'passes': 3,
                'verify': True
            },
            'memory_protection': {
                'wipe_keys': True,
                'zero_memory': True
            }
        },
        'batch_processing': {
            'max_workers': 4,
            'chunk_size': 1024 * 1024,
            'progress_updates': True,
            'continue_on_error': False
        },
        'output': {
            'verbose': False,
            'progress_bars': True,
            'color_output': True,
            'log_level': 'INFO'
        },
        'paths': {
            'config_directory': '~/.secure-files-cli',
            'keyfile_directory': '~/.secure-files-cli/keys',
            'temp_directory': '~/.secure-files-cli/temp',
            'log_directory': '~/.secure-files-cli/logs'
        }
    }
    
    def __init__(self, config_file: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to configuration file
            profile: Configuration profile to use
        """
        self.config_file = config_file
        self.profile = profile
        self._config = self._deep_copy_dict(self.DEFAULT_CONFIG)
        self._load_config()
    
    def _deep_copy_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Create a deep copy of a dictionary."""
        result = {}
        for key, value in d.items():
            if isinstance(value, dict):
                result[key] = self._deep_copy_dict(value)
            else:
                result[key] = value
        return result
    
    def _expand_path(self, path: str) -> str:
        """Expand user home directory and environment variables."""
        expanded = os.path.expanduser(path)
        expanded = os.path.expandvars(expanded)
        return os.path.abspath(expanded)
    
    def _get_default_config_paths(self) -> list:
        """Get list of default configuration file paths."""
        config_dir = self._expand_path('~/.secure-files-cli')
        
        paths = [
            os.path.join(config_dir, 'config.toml'),
            os.path.join(config_dir, 'config.yaml'),
            os.path.join(config_dir, 'config.yml'),
            os.path.join(config_dir, 'config.json'),
            './secure-files-cli.toml',
            './secure-files-cli.yaml',
            './secure-files-cli.yml',
            './secure-files-cli.json'
        ]
        
        return paths
    
    def _load_config(self) -> None:
        """Load configuration from file and environment variables."""
        # Load from file
        if self.config_file:
            self._load_from_file(self.config_file)
        else:
            # Try default locations
            for path in self._get_default_config_paths():
                if os.path.exists(path):
                    self._load_from_file(path)
                    self.config_file = path
                    break
        
        # Load environment variables
        self._load_from_environment()
        
        # Apply profile if specified
        if self.profile:
            self._apply_profile(self.profile)
    
    def _load_from_file(self, file_path: str) -> None:
        """Load configuration from a file."""
        try:
            file_path = self._expand_path(file_path)
            
            with open(file_path, 'r') as f:
                if file_path.endswith('.toml') and TOML_AVAILABLE:
                    file_config = toml.load(f)
                elif file_path.endswith(('.yaml', '.yml')) and YAML_AVAILABLE:
                    file_config = yaml.safe_load(f)
                elif file_path.endswith('.json'):
                    file_config = json.load(f)
                else:
                    raise ConfigError(f"Unsupported config file format: {file_path}")
            
            self._merge_config(file_config)
            
        except Exception as e:
            raise ConfigError(f"Failed to load config from {file_path}: {e}")
    
    def _load_from_environment(self) -> None:
        """Load configuration from environment variables."""
        env_mappings = {
            'SECURE_FILES_CLI_ITERATIONS': ('encryption', 'iterations', int),
            'SECURE_FILES_CLI_HASH_ALGORITHM': ('encryption', 'hash_algorithm', str),
            'SECURE_FILES_CLI_BUFFER_SIZE': ('encryption', 'buffer_size', int),
            'SECURE_FILES_CLI_COMPRESSION_ENABLED': ('encryption', 'compression', 'enabled', bool),
            'SECURE_FILES_CLI_COMPRESSION_ALGORITHM': ('encryption', 'compression', 'algorithm', str),
            'SECURE_FILES_CLI_COMPRESSION_LEVEL': ('encryption', 'compression', 'level', int),
            'SECURE_FILES_CLI_VERBOSE': ('output', 'verbose', bool),
            'SECURE_FILES_CLI_LOG_LEVEL': ('output', 'log_level', str),
            'SECURE_FILES_CLI_MAX_WORKERS': ('batch_processing', 'max_workers', int),
            'SECURE_FILES_CLI_CONFIG_DIR': ('paths', 'config_directory', str),
            'SECURE_FILES_CLI_KEYFILE_DIR': ('paths', 'keyfile_directory', str),
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Convert to appropriate type
                if len(config_path) >= 3 and config_path[-1] in (int, bool, str):
                    type_func = config_path[-1]
                    config_path = config_path[:-1]
                else:
                    type_func = str
                
                try:
                    if type_func == bool:
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    elif type_func == int:
                        value = int(value)
                    
                    self._set_nested_value(config_path, value)
                except (ValueError, TypeError):
                    pass  # Skip invalid environment variable values
    
    def _apply_profile(self, profile_name: str) -> None:
        """Apply a configuration profile."""
        profiles_file = self._expand_path('~/.secure-files-cli/profiles.toml')
        
        if not os.path.exists(profiles_file):
            raise ConfigError(f"Profile not found: {profile_name}")
        
        try:
            with open(profiles_file, 'r') as f:
                if TOML_AVAILABLE:
                    profiles = toml.load(f)
                else:
                    profiles = json.load(f)
            
            if profile_name not in profiles:
                raise ConfigError(f"Profile not found: {profile_name}")
            
            profile_config = profiles[profile_name]
            self._merge_config(profile_config)
            
        except Exception as e:
            raise ConfigError(f"Failed to apply profile {profile_name}: {e}")
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
        """Merge new configuration with existing configuration."""
        self._deep_merge(self._config, new_config)
    
    def _deep_merge(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Deep merge source dictionary into target dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def _set_nested_value(self, path: tuple, value: Any) -> None:
        """Set a nested configuration value."""
        current = self._config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        current = self._config
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split('.')
        current = self._config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def save(self, file_path: Optional[str] = None) -> None:
        """
        Save configuration to file.
        
        Args:
            file_path: Path to save configuration (uses current file if None)
        """
        save_path = file_path or self.config_file
        
        if not save_path:
            raise ConfigError("No configuration file specified")
        
        save_path = self._expand_path(save_path)
        
        # Create directory if needed
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        try:
            with open(save_path, 'w') as f:
                if save_path.endswith('.toml') and TOML_AVAILABLE:
                    toml.dump(self._config, f)
                elif save_path.endswith(('.yaml', '.yml')) and YAML_AVAILABLE:
                    yaml.dump(self._config, f, default_flow_style=False)
                elif save_path.endswith('.json'):
                    json.dump(self._config, f, indent=2)
                else:
                    raise ConfigError(f"Unsupported config file format: {save_path}")
            
            self.config_file = save_path
            
        except Exception as e:
            raise ConfigError(f"Failed to save config to {save_path}: {e}")
    
    def create_profile(self, profile_name: str, config_overrides: Dict[str, Any]) -> None:
        """
        Create a new configuration profile.
        
        Args:
            profile_name: Name of the profile
            config_overrides: Configuration overrides for the profile
        """
        profiles_dir = self._expand_path('~/.secure-files-cli/profiles')
        os.makedirs(profiles_dir, exist_ok=True)
        
        profiles_file = os.path.join(profiles_dir, 'profiles.toml')
        
        # Load existing profiles
        profiles = {}
        if os.path.exists(profiles_file):
            try:
                with open(profiles_file, 'r') as f:
                    if TOML_AVAILABLE:
                        profiles = toml.load(f)
                    else:
                        profiles = json.load(f)
            except:
                pass
        
        # Add new profile
        profiles[profile_name] = config_overrides
        
        # Save profiles
        try:
            with open(profiles_file, 'w') as f:
                if TOML_AVAILABLE:
                    toml.dump(profiles, f)
                else:
                    json.dump(profiles, f, indent=2)
        except Exception as e:
            raise ConfigError(f"Failed to save profile: {e}")
    
    def list_profiles(self) -> list:
        """List available configuration profiles."""
        profiles_file = self._expand_path('~/.secure-files-cli/profiles.toml')
        
        if not os.path.exists(profiles_file):
            return []
        
        try:
            with open(profiles_file, 'r') as f:
                if TOML_AVAILABLE:
                    profiles = toml.load(f)
                else:
                    profiles = json.load(f)
            
            return list(profiles.keys())
            
        except:
            return []
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values."""
        self._config = self._deep_copy_dict(self.DEFAULT_CONFIG)
    
    def validate(self) -> bool:
        """
        Validate configuration values.
        
        Returns:
            True if configuration is valid
        """
        try:
            # Validate encryption settings
            iterations = self.get('encryption.iterations')
            if not isinstance(iterations, int) or iterations < 1000:
                return False
            
            buffer_size = self.get('encryption.buffer_size')
            if not isinstance(buffer_size, int) or buffer_size < 1024:
                return False
            
            # Validate paths
            config_dir = self.get('paths.config_directory')
            if not config_dir or not isinstance(config_dir, str):
                return False
            
            return True
            
        except:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        return self._deep_copy_dict(self._config)
    
    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access."""
        return self.get(key)
    
    def __setitem__(self, key: str, value: Any) -> None:
        """Allow dictionary-style assignment."""
        self.set(key, value)
    
    def __contains__(self, key: str) -> bool:
        """Check if configuration contains key."""
        return self.get(key) is not None


def load_config(config_file: Optional[str] = None, profile: Optional[str] = None) -> Config:
    """
    Load configuration from file or defaults.
    
    Args:
        config_file: Path to configuration file
        profile: Configuration profile to use
        
    Returns:
        Config object
    """
    return Config(config_file, profile)


def create_default_config(config_file: str) -> None:
    """
    Create a default configuration file.
    
    Args:
        config_file: Path where to create the config file
    """
    config = Config()
    config.save(config_file)


def get_config_directory() -> str:
    """Get the configuration directory path."""
    config = Config()
    return config._expand_path(config.get('paths.config_directory'))


def ensure_config_directories() -> None:
    """Ensure all configuration directories exist."""
    config = Config()
    
    directories = [
        config.get('paths.config_directory'),
        config.get('paths.keyfile_directory'),
        config.get('paths.temp_directory'),
        config.get('paths.log_directory'),
        config.get('key_management.backup_directory'),
    ]
    
    for directory in directories:
        if directory:
            expanded_dir = config._expand_path(directory)
            os.makedirs(expanded_dir, exist_ok=True)