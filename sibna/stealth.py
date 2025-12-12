#!/usr/bin/env python3
"""
Obsidian Sovereign - Stealth Layer
Traffic obfuscation and timing randomization to prevent protocol fingerprinting
"""

import os
import time
import random
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class StealthLayer:
    """
    Implements traffic obfuscation and timing randomization.
    
    Features:
    - Random padding (0-1024 bytes)
    - Timing jitter (0-100ms)
    - Dummy packet injection
    - Pattern hiding
    """
    
    def __init__(
        self,
        min_padding: int = 0,
        max_padding: int = 1024,
        jitter_min: float = 0.0,
        jitter_max: float = 0.1,
        dummy_packet_probability: float = 0.1
    ):
        """
        Initialize stealth layer.
        
        Args:
            min_padding: Minimum random padding bytes
            max_padding: Maximum random padding bytes
            jitter_min: Minimum timing jitter in seconds
            jitter_max: Maximum timing jitter in seconds
            dummy_packet_probability: Probability of injecting dummy packet (0.0-1.0)
        """
        self.min_padding = min_padding
        self.max_padding = max_padding
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.dummy_packet_probability = dummy_packet_probability
        
        logger.info(
            f"Stealth layer initialized: padding={min_padding}-{max_padding}, "
            f"jitter={jitter_min*1000:.1f}-{jitter_max*1000:.1f}ms"
        )
    
    def obfuscate(self, data: bytes) -> bytes:
        """
        Obfuscate data with random padding.
        
        Format: [padding_length(2 bytes)][original_data][random_padding]
        
        Args:
            data: Original data to obfuscate
            
        Returns:
            Obfuscated data with padding
        """
        # Generate random padding
        padding_length = random.randint(self.min_padding, self.max_padding)
        padding = os.urandom(padding_length)
        
        # Pack: length (2 bytes, big-endian) + data + padding
        padding_length_bytes = padding_length.to_bytes(2, byteorder='big')
        obfuscated = padding_length_bytes + data + padding
        
        logger.debug(f"Obfuscated {len(data)} bytes -> {len(obfuscated)} bytes (+{padding_length} padding)")
        
        return obfuscated
    
    def deobfuscate(self, obfuscated: bytes) -> bytes:
        """
        Remove obfuscation padding.
        
        Args:
            obfuscated: Obfuscated data
            
        Returns:
            Original data without padding
            
        Raises:
            ValueError: If data format is invalid
        """
        if len(obfuscated) < 2:
            raise ValueError("Obfuscated data too short")
        
        # Extract padding length
        padding_length = int.from_bytes(obfuscated[:2], byteorder='big')
        
        # Validate padding length
        if padding_length < self.min_padding or padding_length > self.max_padding:
            raise ValueError(f"Invalid padding length: {padding_length}")
        
        # Calculate data length
        data_length = len(obfuscated) - 2 - padding_length
        
        if data_length < 0:
            raise ValueError("Invalid obfuscated data format")
        
        # Extract original data
        data = obfuscated[2:2+data_length]
        
        logger.debug(f"Deobfuscated {len(obfuscated)} bytes -> {len(data)} bytes")
        
        return data
    
    def apply_jitter(self) -> None:
        """
        Apply random timing jitter to prevent timing analysis.
        
        Sleeps for a random duration between jitter_min and jitter_max.
        """
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        time.sleep(jitter)
        logger.debug(f"Applied jitter: {jitter*1000:.2f}ms")
    
    def should_inject_dummy(self) -> bool:
        """
        Determine if a dummy packet should be injected.
        
        Returns:
            True if dummy packet should be sent
        """
        return random.random() < self.dummy_packet_probability
    
    def generate_dummy_packet(self, min_size: int = 64, max_size: int = 512) -> bytes:
        """
        Generate a dummy packet with random data.
        
        Args:
            min_size: Minimum dummy packet size
            max_size: Maximum dummy packet size
            
        Returns:
            Random dummy packet data
        """
        size = random.randint(min_size, max_size)
        dummy = os.urandom(size)
        
        logger.debug(f"Generated dummy packet: {size} bytes")
        
        return dummy
    
    def mimic_https_timing(self) -> None:
        """
        Mimic HTTPS connection timing patterns.
        
        Adds realistic delays that match typical HTTPS traffic:
        - Initial handshake delay
        - Request processing delay
        - Response delay
        """
        # Mimic TLS handshake (20-50ms)
        handshake_delay = random.uniform(0.02, 0.05)
        time.sleep(handshake_delay)
        
        # Mimic server processing (10-30ms)
        processing_delay = random.uniform(0.01, 0.03)
        time.sleep(processing_delay)
        
        logger.debug(
            f"HTTPS timing mimicry: handshake={handshake_delay*1000:.1f}ms, "
            f"processing={processing_delay*1000:.1f}ms"
        )
    
    def add_decoy_headers(self, data: bytes) -> bytes:
        """
        Add decoy headers to make traffic look like HTTPS.
        
        Args:
            data: Original data
            
        Returns:
            Data with decoy headers
        """
        # Add fake HTTP/2 frame header (9 bytes)
        # Format: Length(3) + Type(1) + Flags(1) + Stream ID(4)
        frame_length = len(data)
        frame_type = 0x00  # DATA frame
        frame_flags = 0x01  # END_STREAM
        stream_id = random.randint(1, 100)
        
        header = (
            frame_length.to_bytes(3, byteorder='big') +
            frame_type.to_bytes(1, byteorder='big') +
            frame_flags.to_bytes(1, byteorder='big') +
            stream_id.to_bytes(4, byteorder='big')
        )
        
        return header + data
    
    def remove_decoy_headers(self, data: bytes) -> bytes:
        """
        Remove decoy headers.
        
        Args:
            data: Data with decoy headers
            
        Returns:
            Original data without headers
        """
        if len(data) < 9:
            raise ValueError("Data too short to contain headers")
        
        # Skip 9-byte HTTP/2 frame header
        return data[9:]


class TrafficShaper:
    """
    Shape traffic to match specific patterns (e.g., HTTPS, WebSocket).
    """
    
    def __init__(self, target_pattern: str = "https"):
        """
        Initialize traffic shaper.
        
        Args:
            target_pattern: Pattern to mimic ('https', 'websocket', 'dns')
        """
        self.target_pattern = target_pattern
        logger.info(f"Traffic shaper initialized: pattern={target_pattern}")
    
    def shape(self, data: bytes) -> bytes:
        """
        Shape data to match target pattern.
        
        Args:
            data: Original data
            
        Returns:
            Shaped data
        """
        if self.target_pattern == "https":
            return self._shape_https(data)
        elif self.target_pattern == "websocket":
            return self._shape_websocket(data)
        else:
            return data
    
    def _shape_https(self, data: bytes) -> bytes:
        """Shape data to look like HTTPS traffic."""
        # Add TLS record header (5 bytes)
        # Content Type (1) + Version (2) + Length (2)
        content_type = 0x17  # Application Data
        version = b'\x03\x03'  # TLS 1.2
        length = len(data).to_bytes(2, byteorder='big')
        
        header = bytes([content_type]) + version + length
        return header + data
    
    def _shape_websocket(self, data: bytes) -> bytes:
        """Shape data to look like WebSocket traffic."""
        # Add WebSocket frame header
        fin_opcode = 0x82  # FIN + Binary frame
        
        # Payload length
        length = len(data)
        if length < 126:
            header = bytes([fin_opcode, length])
        elif length < 65536:
            header = bytes([fin_opcode, 126]) + length.to_bytes(2, byteorder='big')
        else:
            header = bytes([fin_opcode, 127]) + length.to_bytes(8, byteorder='big')
        
        return header + data
    
    def unshape(self, shaped_data: bytes) -> bytes:
        """
        Remove shaping from data.
        
        Args:
            shaped_data: Shaped data
            
        Returns:
            Original data
        """
        if self.target_pattern == "https":
            return self._unshape_https(shaped_data)
        elif self.target_pattern == "websocket":
            return self._unshape_websocket(shaped_data)
        else:
            return shaped_data
    
    def _unshape_https(self, data: bytes) -> bytes:
        """Remove HTTPS shaping."""
        if len(data) < 5:
            raise ValueError("Data too short for HTTPS record")
        return data[5:]  # Skip 5-byte TLS record header
    
    def _unshape_websocket(self, data: bytes) -> bytes:
        """Remove WebSocket shaping."""
        if len(data) < 2:
            raise ValueError("Data too short for WebSocket frame")
        
        # Parse payload length
        payload_len = data[1] & 0x7F
        
        if payload_len < 126:
            return data[2:]
        elif payload_len == 126:
            return data[4:]
        else:  # payload_len == 127
            return data[10:]


# Convenience functions
def create_stealth_layer(
    padding_range: tuple = (0, 1024),
    jitter_range: tuple = (0.0, 0.1)
) -> StealthLayer:
    """
    Create a stealth layer with specified parameters.
    
    Args:
        padding_range: (min, max) padding in bytes
        jitter_range: (min, max) jitter in seconds
        
    Returns:
        Configured StealthLayer instance
    """
    return StealthLayer(
        min_padding=padding_range[0],
        max_padding=padding_range[1],
        jitter_min=jitter_range[0],
        jitter_max=jitter_range[1]
    )
