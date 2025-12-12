import zlib
import lz4.frame
import logging
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)

class CompressionMethod(Enum):
    NONE = 0
    ZLIB = 1
    LZ4 = 2

class DataCompressor:
    def __init__(self, method: CompressionMethod = CompressionMethod.LZ4, level: int = 6):
        self.method = method
        self.level = level
        
    def compress(self, data: bytes) -> bytes:
        """ضغط البيانات مع التعامل مع الأخطاء"""
        if not data or self.method == CompressionMethod.NONE:
            return data
            
        try:
            if self.method == CompressionMethod.ZLIB:
                return zlib.compress(data, level=self.level)
            elif self.method == CompressionMethod.LZ4:
                return lz4.frame.compress(data, compression_level=self.level)
            else:
                return data
        except Exception as e:
            logger.error(f"Compression failed: {e}, falling back to no compression")
            return data
    
    def decompress(self, compressed_data: bytes) -> Optional[bytes]:
        """فك ضغط البيانات مع التعامل مع الأخطاء"""
        if not compressed_data or self.method == CompressionMethod.NONE:
            return compressed_data
            
        try:
            if self.method == CompressionMethod.ZLIB:
                return zlib.decompress(compressed_data)
            elif self.method == CompressionMethod.LZ4:
                return lz4.frame.decompress(compressed_data)
            else:
                return compressed_data
        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            return None

# ✅ ضاغط افتراضي
default_compressor = DataCompressor(CompressionMethod.LZ4)

# Convenience functions for easy import
def compress(data: bytes) -> bytes:
    """Compress data using default compressor (LZ4)"""
    return default_compressor.compress(data)

def decompress(data: bytes) -> Optional[bytes]:
    """Decompress data using default compressor (LZ4)"""
    return default_compressor.decompress(data)