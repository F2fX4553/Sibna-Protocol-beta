import struct
from typing import Tuple, Optional
from .config import PROTOCOL_VER

def pack(data: bytes) -> bytes:
    return struct.pack('>BI', PROTOCOL_VER, len(data)) + data

def unpack(buffer: bytes) -> Tuple[Optional[bytes], bytes]:
    if len(buffer) < 5:
        return None, buffer
    
    version, length = struct.unpack('>BI', buffer[:5])
    
    if version != PROTOCOL_VER:
        return None, buffer  # Protocol mismatch
    
    if len(buffer) < 5 + length:
        return None, buffer
    
    data = buffer[5:5+length]
    remaining = buffer[5+length:]
    return data, remaining

# تصدير صريح
__all__ = ['pack', 'unpack']