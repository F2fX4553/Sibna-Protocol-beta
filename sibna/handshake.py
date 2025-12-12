import logging
import time
import struct
import base64
from typing import Optional, Tuple, Dict
from .crypto import KeyExchange, Signer, MultiLayerEncryptor
from .key_manager import default_key_manager

logger = logging.getLogger(__name__)

class HandshakeError(Exception):
    pass

class SecureHandshake:
    PROTOCOL_VERSION = 2
    
    # Sizes
    CLASSICAL_PK_SIZE = 32
    HYBRID_PK_SIZE = CLASSICAL_PK_SIZE # 32
    
    def __init__(self, key_manager=default_key_manager):
        self.key_manager = key_manager
        self.ephemeral_key = KeyExchange()
        self.peer_identity_key: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        
    def create_client_hello(self) -> bytes:
        """
        ClientHello:
        - Version (2 bytes)
        - Timestamp (8 bytes)
        - Ephemeral Hybrid Public Key (32 bytes)
        """
        version = struct.pack("!H", self.PROTOCOL_VERSION)
        timestamp = struct.pack("!d", time.time())
        pub_key = self.ephemeral_key.get_public_bytes()
        
        return version + timestamp + pub_key

    def process_client_hello(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Process ClientHello and generate ServerHello
        Returns: (ServerHello, SharedSecret)
        """
        min_len = 10 + self.HYBRID_PK_SIZE
        if len(data) < min_len:
            raise HandshakeError(f"ClientHello too short: {len(data)} < {min_len}")
            
        version = struct.unpack("!H", data[:2])[0]
        if version != self.PROTOCOL_VERSION:
            raise HandshakeError(f"Protocol version mismatch: {version} != {self.PROTOCOL_VERSION}")
            
        client_pub_key = data[10:10+self.HYBRID_PK_SIZE]
        
        # Generate Shared Secret using X25519
        shared_secret = self.ephemeral_key.exchange(client_pub_key)
        
        # ServerHello:
        # - Version (2 bytes)
        # - Server Ephemeral Classical PK (32 bytes)
        # ...existing code...
        # - Identity Public Key (32 bytes)
        # - Signature (64 bytes) over (ClientHello + ServerHelloParams)
        
        server_classical_pub = self.ephemeral_key.get_public_bytes()
        identity_pub = self.key_manager.get_identity_public_key()
        
        params = (
            struct.pack("!H", self.PROTOCOL_VERSION) + 
            server_classical_pub + 
            identity_pub
        )
        
        # Sign (ClientHello + Params) to bind session
        signature = self.key_manager.sign_data(data + params)
        
        server_hello = params + signature
        return server_hello, shared_secret

    def process_server_hello(self, client_hello: bytes, server_hello: bytes) -> bytes:
        """
        Process ServerHello and generate Shared Secret
        """
        # Sizes: 2 + 32 + 32 + 64 = 130
        expected_len = 2 + self.CLASSICAL_PK_SIZE + 32 + 64
        if len(server_hello) < expected_len:
            raise HandshakeError(f"ServerHello too short: {len(server_hello)} < {expected_len}")
            
        version = struct.unpack("!H", server_hello[:2])[0]
        if version != self.PROTOCOL_VERSION:
            raise HandshakeError("Protocol version mismatch")
            
        # Parse fields
        offset = 2
        server_classical_pub = server_hello[offset : offset + self.CLASSICAL_PK_SIZE]
        offset += self.CLASSICAL_PK_SIZE
        
        server_identity_pub = server_hello[offset : offset + 32]
        offset += 32
        
        signature = server_hello[offset : offset + 64]
        
        # Verify Signature
        # Signed data = ClientHello + ServerHelloParams (up to signature)
        params = server_hello[:offset]
        try:
            Signer.verify(server_identity_pub, signature, client_hello + params)
        except Exception:
            raise HandshakeError("Server signature verification failed")
            
        self.peer_identity_key = server_identity_pub
        
        # Derive Shared Secret using X25519
        shared_secret = self.ephemeral_key.exchange(server_classical_pub)
        return shared_secret

    def create_client_finished(self, server_hello: bytes, shared_secret: bytes) -> bytes:
        """
        ClientFinished:
        - Identity Public Key (32 bytes)
        - Signature (64 bytes) over (ServerHello + IdentityPubKey)
        """
        identity_pub = self.key_manager.get_identity_public_key()
        
        # Sign ServerHello + MyIdentity to prove I am who I say I am and I saw ServerHello
        signature = self.key_manager.sign_data(server_hello + identity_pub)
        
        return identity_pub + signature

    def process_client_finished(self, server_hello: bytes, client_finished: bytes):
        """
        Verify ClientFinished
        """
        if len(client_finished) < 96:
            raise HandshakeError("ClientFinished too short")
            
        client_identity_pub = client_finished[:32]
        signature = client_finished[32:]
        
        try:
            Signer.verify(client_identity_pub, signature, server_hello + client_identity_pub)
        except Exception:
            raise HandshakeError("Client signature verification failed")
            
        self.peer_identity_key = client_identity_pub
        logger.info(f"✅ Handshake completed with peer: {base64.b64encode(client_identity_pub).decode()[:8]}...")