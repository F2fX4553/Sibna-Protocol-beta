import logging
import base64
from .base import Transport

logger = logging.getLogger(__name__)

class DnsTransport(Transport):
    """
    Simulated DNS Tunnel Transport.
    Encodes data into fake DNS queries/responses.
    """
    def __init__(self, socket):
        self.socket = socket
        logger.info("DNS Transport Initialized (Simulated)")

    def send(self, data: bytes) -> None:
        # Encode data as subdomain
        # e.g., <base64>.example.com
        encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')
        
        # Split into chunks if needed (DNS label limit is 63 chars)
        # For simulation, we just send it as a "DNS Packet" structure
        # Transaction ID (2) + Flags (2) + Questions (2) ...
        dns_packet = b'\x00\x01\x01\x00' + encoded.encode()
        self.socket.sendall(dns_packet)

    def recv(self) -> bytes:
        data = self.socket.recv(4096)
        # Decode "DNS Packet"
        if len(data) > 4:
            payload = data[4:]
            try:
                return base64.urlsafe_b64decode(payload + b'==')
            except:
                return payload
        return data

    def close(self):
        self.socket.close()
