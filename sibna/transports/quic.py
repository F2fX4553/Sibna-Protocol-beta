import logging
from .base import Transport

logger = logging.getLogger(__name__)

class QuicTransport(Transport):
    """
    Simulated QUIC Transport (UDP-like).
    """
    def __init__(self, socket):
        self.socket = socket
        logger.info("QUIC Transport Initialized (Simulated)")

    def send(self, data: bytes) -> None:
        # QUIC Short Header simulation
        # 0x40 | Packet Number
        header = b'\x40\x01\x02\x03'
        self.socket.sendall(header + data)

    def recv(self) -> bytes:
        data = self.socket.recv(4096)
        if len(data) > 4:
            return data[4:]
        return data

    def close(self):
        self.socket.close()
