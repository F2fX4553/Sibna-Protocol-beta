import logging
import time
from .base import Transport

logger = logging.getLogger(__name__)

class WebRtcTransport(Transport):
    """
    Simulated WebRTC Transport.
    Mimics DTLS/SRTP traffic patterns.
    """
    def __init__(self, socket):
        self.socket = socket
        logger.info("WebRTC Transport Initialized (Simulated)")

    def send(self, data: bytes) -> None:
        # Wrap in fake RTP/DTLS header
        # RTP Header is 12 bytes
        rtp_header = b'\x80\x00\x00\x00' + time.time_ns().to_bytes(8, 'big')
        payload = rtp_header + data
        self.socket.sendall(payload)

    def recv(self) -> bytes:
        # Unwrap fake RTP
        data = self.socket.recv(4096)
        if len(data) > 12:
            return data[12:] # Strip RTP header
        return data

    def close(self):
        self.socket.close()
