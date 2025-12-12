import socket
import ssl
import logging
from typing import Optional
from .config import SOCKET_TIMEOUT, MAX_PACKET_SIZE, get_fake_host, get_fake_path
from .jitter import apply_traffic_shaping

logger = logging.getLogger(__name__)

class StealthTransport:
    def __init__(self, sock: socket.socket, use_tls: bool = True, server_side: bool = False, 
                 hostname: Optional[str] = None, allow_insecure_fallback: bool = False):
        self.sock = sock
        self.sock.settimeout(SOCKET_TIMEOUT)
        self.use_tls = use_tls
        self.server_side = server_side
        self.hostname = hostname
        self.allow_insecure_fallback = allow_insecure_fallback

        self._tls_context = None
        self._tls_socket = None
        
        # Initialize Stealth Layer
        from .stealth import create_stealth_layer
        self.stealth = create_stealth_layer()

        if self.use_tls:
            self._setup_secure_tls()

    def _setup_secure_tls(self):
        """Setup secure TLS"""
        try:
            self._tls_context = ssl.create_default_context()
            
            if self.server_side:
                self._tls_socket = self._tls_context.wrap_socket(
                    self.sock,
                    server_side=True,
                    do_handshake_on_connect=True
                )
            else:
                self._tls_socket = self._tls_context.wrap_socket(
                    self.sock,
                    server_side=False,
                    do_handshake_on_connect=True,
                    server_hostname=self.hostname or get_fake_host()
                )
                
            self._tls_socket.settimeout(SOCKET_TIMEOUT)

        except Exception as e:
            logger.critical(f"TLS Handshake Failed: {e}")
            
            if self.allow_insecure_fallback:
                logger.warning("Using insecure fallback (not recommended)")
                self.use_tls = False
                self._tls_socket = None
            else:
                raise ConnectionError("Secure TLS connection failed - Downgrade prevented")

    def send(self, data: bytes) -> None:
        apply_traffic_shaping()
        
        # Apply Stealth Layer Obfuscation
        obfuscated_data = self.stealth.obfuscate(data)

        if self.use_tls and self._tls_socket:
            length = len(obfuscated_data).to_bytes(4, 'big')
            self._tls_socket.sendall(length + obfuscated_data)
            return

        if self.allow_insecure_fallback:
            fake_host = get_fake_host()
            fake_path = get_fake_path()
            header = (
                f"POST {fake_path} HTTP/1.1\r\n"
                f"Host: {fake_host}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(obfuscated_data)}\r\n\r\n"
            ).encode()

            self.sock.sendall(header + obfuscated_data)
        else:
            raise ConnectionError("TLS failed and insecure fallback is disabled")

    def recv(self) -> Optional[bytes]:
        if self.use_tls and self._tls_socket:
            try:
                length_data = self._recv_exact(4)
                if not length_data:
                    return None

                packet_len = int.from_bytes(length_data, 'big')
                if packet_len <= 0 or packet_len > MAX_PACKET_SIZE:
                    return None

                obfuscated_data = self._recv_exact(packet_len)
                if not obfuscated_data:
                    return None
                    
                return self.stealth.deobfuscate(obfuscated_data)

            except Exception:
                return None

        if self.allow_insecure_fallback:
            obfuscated_data = self._recv_http_fallback()
            if not obfuscated_data:
                return None
            return self.stealth.deobfuscate(obfuscated_data)
        else:
            return None

    def _recv_exact(self, length: int) -> Optional[bytes]:
        data = b""
        while len(data) < length:
            try:
                chunk = (
                    self._tls_socket.recv(length - len(data))
                    if (self.use_tls and self._tls_socket)
                    else self.sock.recv(length - len(data))
                )

                if not chunk:
                    return None

                data += chunk

            except Exception:
                return None

        return data

    def _recv_http_fallback(self) -> Optional[bytes]:
        header = b""

        while b"\r\n\r\n" not in header:
            try:
                chunk = self.sock.recv(1)
                if not chunk:
                    return None

                header += chunk

                if len(header) > 4096:
                    return None

            except Exception:
                return None

        try:
            header_str = header.decode('utf-8', errors='ignore')
            content_length_line = [
                line for line in header_str.split("\r\n") if "Content-Length:" in line
            ][0]

            length = int(content_length_line.split(":")[1].strip())

        except Exception:
            return None

        if length < 0 or length > MAX_PACKET_SIZE:
            return None

        return self._recv_exact(length)

    def close(self) -> None:
        try:
            if self._tls_socket:
                self._tls_socket.close()
            if self.sock:
                self.sock.close()
        except Exception:
            pass

__all__ = ["StealthTransport"]