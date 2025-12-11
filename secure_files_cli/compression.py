"""
Compression Module

Handles data compression with multiple algorithms.
Supports gzip, lzma, and bz2 compression with configurable levels.
"""

import io
import gzip
import lzma
import bz2
from typing import Union, Optional, Tuple, BinaryIO

try:
    import zlib
    ZLIB_AVAILABLE = True
except ImportError:
    ZLIB_AVAILABLE = False


class CompressionError(Exception):
    """Raised when compression operations fail."""
    pass


class CompressionAlgorithm:
    """Base class for compression algorithms."""
    
    def __init__(self, name: str, extension: str):
        self.name = name
        self.extension = extension
    
    def compress(self, data: bytes, level: int = 6) -> bytes:
        """Compress data."""
        raise NotImplementedError
    
    def decompress(self, compressed_data: bytes) -> bytes:
        """Decompress data."""
        raise NotImplementedError
    
    def compress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, level: int = 6) -> None:
        """Compress from input stream to output stream."""
        raise NotImplementedError
    
    def decompress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """Decompress from input stream to output stream."""
        raise NotImplementedError


class GzipCompression(CompressionAlgorithm):
    """Gzip compression algorithm."""
    
    def __init__(self):
        super().__init__("gzip", ".gz")
    
    def compress(self, data: bytes, level: int = 6) -> bytes:
        """Compress data using gzip."""
        try:
            return gzip.compress(data, compresslevel=level)
        except Exception as e:
            raise CompressionError(f"Gzip compression failed: {e}")
    
    def decompress(self, compressed_data: bytes) -> bytes:
        """Decompress gzip data."""
        try:
            return gzip.decompress(compressed_data)
        except Exception as e:
            raise CompressionError(f"Gzip decompression failed: {e}")
    
    def compress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, level: int = 6) -> None:
        """Compress stream using gzip."""
        try:
            with gzip.GzipFile(fileobj=output_stream, mode='wb', compresslevel=level) as gz_file:
                while True:
                    chunk = input_stream.read(8192)
                    if not chunk:
                        break
                    gz_file.write(chunk)
        except Exception as e:
            raise CompressionError(f"Gzip stream compression failed: {e}")
    
    def decompress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """Decompress gzip stream."""
        try:
            with gzip.GzipFile(fileobj=input_stream, mode='rb') as gz_file:
                while True:
                    chunk = gz_file.read(8192)
                    if not chunk:
                        break
                    output_stream.write(chunk)
        except Exception as e:
            raise CompressionError(f"Gzip stream decompression failed: {e}")


class LzmaCompression(CompressionAlgorithm):
    """LZMA (xz) compression algorithm."""
    
    def __init__(self):
        super().__init__("lzma", ".xz")
    
    def compress(self, data: bytes, level: int = 6) -> bytes:
        """Compress data using LZMA."""
        try:
            return lzma.compress(data, preset=level)
        except Exception as e:
            raise CompressionError(f"LZMA compression failed: {e}")
    
    def decompress(self, compressed_data: bytes) -> bytes:
        """Decompress LZMA data."""
        try:
            return lzma.decompress(compressed_data)
        except Exception as e:
            raise CompressionError(f"LZMA decompression failed: {e}")
    
    def compress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, level: int = 6) -> None:
        """Compress stream using LZMA."""
        try:
            with lzma.LZMAFile(output_stream, mode='wb', preset=level) as lzma_file:
                while True:
                    chunk = input_stream.read(8192)
                    if not chunk:
                        break
                    lzma_file.write(chunk)
        except Exception as e:
            raise CompressionError(f"LZMA stream compression failed: {e}")
    
    def decompress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """Decompress LZMA stream."""
        try:
            with lzma.LZMAFile(input_stream, mode='rb') as lzma_file:
                while True:
                    chunk = lzma_file.read(8192)
                    if not chunk:
                        break
                    output_stream.write(chunk)
        except Exception as e:
            raise CompressionError(f"LZMA stream decompression failed: {e}")


class Bz2Compression(CompressionAlgorithm):
    """Bzip2 compression algorithm."""
    
    def __init__(self):
        super().__init__("bz2", ".bz2")
    
    def compress(self, data: bytes, level: int = 6) -> bytes:
        """Compress data using bzip2."""
        try:
            return bz2.compress(data, compresslevel=level)
        except Exception as e:
            raise CompressionError(f"Bzip2 compression failed: {e}")
    
    def decompress(self, compressed_data: bytes) -> bytes:
        """Decompress bzip2 data."""
        try:
            return bz2.decompress(compressed_data)
        except Exception as e:
            raise CompressionError(f"Bzip2 decompression failed: {e}")
    
    def compress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, level: int = 6) -> None:
        """Compress stream using bzip2."""
        try:
            with bz2.BZ2File(output_stream, mode='wb', compresslevel=level) as bz2_file:
                while True:
                    chunk = input_stream.read(8192)
                    if not chunk:
                        break
                    bz2_file.write(chunk)
        except Exception as e:
            raise CompressionError(f"Bzip2 stream compression failed: {e}")
    
    def decompress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """Decompress bzip2 stream."""
        try:
            with bz2.BZ2File(input_stream, mode='rb') as bz2_file:
                while True:
                    chunk = bz2_file.read(8192)
                    if not chunk:
                        break
                    output_stream.write(chunk)
        except Exception as e:
            raise CompressionError(f"Bzip2 stream decompression failed: {e}")


class ZlibCompression(CompressionAlgorithm):
    """Zlib compression algorithm."""
    
    def __init__(self):
        super().__init__("zlib", ".zlib")
    
    def compress(self, data: bytes, level: int = 6) -> bytes:
        """Compress data using zlib."""
        if not ZLIB_AVAILABLE:
            raise CompressionError("Zlib not available")
        
        try:
            return zlib.compress(data, level=level)
        except Exception as e:
            raise CompressionError(f"Zlib compression failed: {e}")
    
    def decompress(self, compressed_data: bytes) -> bytes:
        """Decompress zlib data."""
        if not ZLIB_AVAILABLE:
            raise CompressionError("Zlib not available")
        
        try:
            return zlib.decompress(compressed_data)
        except Exception as e:
            raise CompressionError(f"Zlib decompression failed: {e}")
    
    def compress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, level: int = 6) -> None:
        """Compress stream using zlib."""
        if not ZLIB_AVAILABLE:
            raise CompressionError("Zlib not available")
        
        try:
            compressor = zlib.compressobj(level)
            while True:
                chunk = input_stream.read(8192)
                if not chunk:
                    break
                compressed_chunk = compressor.compress(chunk)
                if compressed_chunk:
                    output_stream.write(compressed_chunk)
            
            # Flush remaining data
            remaining = compressor.flush()
            if remaining:
                output_stream.write(remaining)
        except Exception as e:
            raise CompressionError(f"Zlib stream compression failed: {e}")
    
    def decompress_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """Decompress zlib stream."""
        if not ZLIB_AVAILABLE:
            raise CompressionError("Zlib not available")
        
        try:
            decompressor = zlib.decompressobj()
            while True:
                chunk = input_stream.read(8192)
                if not chunk:
                    break
                decompressed_chunk = decompressor.decompress(chunk)
                if decompressed_chunk:
                    output_stream.write(decompressed_chunk)
            
            # Flush remaining data
            remaining = decompressor.flush()
            if remaining:
                output_stream.write(remaining)
        except Exception as e:
            raise CompressionError(f"Zlib stream decompression failed: {e}")


# Available compression algorithms
COMPRESSION_ALGORITHMS = {
    'gzip': GzipCompression(),
    'lzma': LzmaCompression(),
    'xz': LzmaCompression(),  # Alias for lzma
    'bz2': Bz2Compression(),
    'bzip2': Bz2Compression(),  # Alias for bz2
}

if ZLIB_AVAILABLE:
    COMPRESSION_ALGORITHMS['zlib'] = ZlibCompression()


def get_compression_algorithm(name: str) -> CompressionAlgorithm:
    """
    Get compression algorithm by name.
    
    Args:
        name: Algorithm name
        
    Returns:
        CompressionAlgorithm instance
        
    Raises:
        CompressionError: If algorithm not found
    """
    name = name.lower()
    if name not in COMPRESSION_ALGORITHMS:
        available = ', '.join(COMPRESSION_ALGORITHMS.keys())
        raise CompressionError(f"Unknown compression algorithm: {name}. Available: {available}")
    
    return COMPRESSION_ALGORITHMS[name]


def compress_data(
    data: bytes,
    algorithm: str = "gzip",
    level: int = 6
) -> bytes:
    """
    Compress data using specified algorithm.
    
    Args:
        data: Data to compress
        algorithm: Compression algorithm name
        level: Compression level (1-9)
        
    Returns:
        Compressed data
        
    Raises:
        CompressionError: If compression fails
    """
    compressor = get_compression_algorithm(algorithm)
    return compressor.compress(data, level)


def decompress_data(
    compressed_data: bytes,
    algorithm: str = "gzip"
) -> bytes:
    """
    Decompress data using specified algorithm.
    
    Args:
        compressed_data: Compressed data
        algorithm: Compression algorithm name
        
    Returns:
        Decompressed data
        
    Raises:
        CompressionError: If decompression fails
    """
    compressor = get_compression_algorithm(algorithm)
    return compressor.decompress(compressed_data)


    def compress_file(
        input_path: str,
        output_path: str,
        algorithm: str = "gzip",
        level: int = 6,
        buffer_size: int = 8192
    ) -> None:
        """
        Compress a file using specified algorithm.
        
        Args:
            input_path: Path to input file
            output_path: Path to output compressed file
            algorithm: Compression algorithm name
            level: Compression level (1-9)
            buffer_size: Buffer size for streaming
            
        Raises:
            CompressionError: If compression fails
        """
        try:
            if not os.path.exists(input_path):
                raise CompressionError(f"Input file not found: {input_path}")
            
            compressor = get_compression_algorithm(algorithm)
            
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                compressor.compress_stream(infile, outfile, level)
            
        except Exception as e:
            # Clean up output file on error
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            raise CompressionError(f"File compression failed: {e}")
    
    return output_path


def decompress_file(
    input_path: str,
    output_path: str,
    algorithm: str = "gzip",
    buffer_size: int = 8192
) -> None:
    """
    Decompress a file using specified algorithm.
    
    Args:
        input_path: Path to compressed file
        output_path: Path to output decompressed file
        algorithm: Compression algorithm name
        buffer_size: Buffer size for streaming
        
    Raises:
        CompressionError: If decompression fails
    """
    try:
        import os
        if not os.path.exists(input_path):
            raise CompressionError(f"Input file not found: {input_path}")
        
        compressor = get_compression_algorithm(algorithm)
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            compressor.decompress_stream(infile, outfile)
            
    except Exception as e:
        # Clean up output file on error
        import os
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        raise CompressionError(f"File decompression failed: {e}")


def detect_compression_algorithm(file_path: str) -> Optional[str]:
    """
    Detect compression algorithm from file extension or magic bytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        Algorithm name or None if not detected
    """
    import os
    
    # Check file extension
    _, ext = os.path.splitext(file_path.lower())
    
    extension_map = {
        '.gz': 'gzip',
        '.xz': 'lzma',
        '.lzma': 'lzma',
        '.bz2': 'bz2',
        '.zlib': 'zlib'
    }
    
    if ext in extension_map:
        return extension_map[ext]
    
    # Check magic bytes
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(10)
        
        if magic.startswith(b'\x1f\x8b'):
            return 'gzip'
        elif magic.startswith(b'\xfd7zXZ\x00'):
            return 'lzma'
        elif magic.startswith(b'BZh'):
            return 'bz2'
        elif magic.startswith(b'\x78\x9c') or magic.startswith(b'\x78\x01') or magic.startswith(b'\x78\xda'):
            return 'zlib'
            
    except:
        pass
    
    return None


def get_compression_info(file_path: str) -> dict:
    """
    Get information about a compressed file.
    
    Args:
        file_path: Path to compressed file
        
    Returns:
        Dictionary with compression information
    """
    import os
    
    info = {
        'file_path': file_path,
        'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        'algorithm': None,
        'is_compressed': False
    }
    
    algorithm = detect_compression_algorithm(file_path)
    if algorithm:
        info['algorithm'] = algorithm
        info['is_compressed'] = True
        
        # Try to get uncompressed size
        try:
            compressor = get_compression_algorithm(algorithm)
            with open(file_path, 'rb') as f:
                # Read a small portion to estimate
                compressed_sample = f.read(1024)
                if compressed_sample:
                    # This is just an estimate
                    info['estimated_uncompressed_size'] = len(compressed_sample) * 2
        except:
            pass
    
    return info


def list_compression_algorithms() -> list:
    """
    List available compression algorithms.
    
    Returns:
        List of algorithm names
    """
    return list(COMPRESSION_ALGORITHMS.keys())


def benchmark_compression(
    data: bytes,
    algorithms: Optional[list] = None
) -> dict:
    """
    Benchmark compression algorithms on given data.
    
    Args:
        data: Data to benchmark
        algorithms: List of algorithms to test (all if None)
        
    Returns:
        Dictionary with benchmark results
    """
    if algorithms is None:
        algorithms = list(COMPRESSION_ALGORITHMS.keys())
    
    results = {}
    original_size = len(data)
    
    for algorithm in algorithms:
        try:
            compressor = get_compression_algorithm(algorithm)
            
            # Test compression
            import time
            start_time = time.time()
            compressed = compressor.compress(data)
            compression_time = time.time() - start_time
            
            # Test decompression
            start_time = time.time()
            decompressed = compressor.decompress(compressed)
            decompression_time = time.time() - start_time
            
            # Calculate metrics
            compression_ratio = len(compressed) / original_size
            space_savings = 1 - compression_ratio
            
            results[algorithm] = {
                'original_size': original_size,
                'compressed_size': len(compressed),
                'compression_ratio': compression_ratio,
                'space_savings': space_savings,
                'compression_time': compression_time,
                'decompression_time': decompression_time,
                'verified': decompressed == data
            }
            
        except Exception as e:
            results[algorithm] = {
                'error': str(e)
            }
    
    return results