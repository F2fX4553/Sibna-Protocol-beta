import os
import time
import json
import hashlib
import base64
from typing import Dict, Optional, List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class Certificate:
    """
    Identity Certificate.
    Binds a Public Key to a User ID and Hardware ID.
    Signed by a CA (or self-signed for P2P web of trust).
    """
    def __init__(self, user_id: str, public_key_bytes: bytes, hardware_id: str, valid_until: int):
        self.user_id = user_id
        self.public_key_bytes = public_key_bytes
        self.hardware_id = hardware_id
        self.valid_until = valid_until
        self.signature = b''
        self.issuer_id = ''

    def to_bytes(self) -> bytes:
        data = {
            "uid": self.user_id,
            "pk": base64.b64encode(self.public_key_bytes).decode(),
            "hw": self.hardware_id,
            "exp": self.valid_until,
            "iss": self.issuer_id
        }
        return json.dumps(data, sort_keys=True).encode()

    def sign(self, issuer_key: ed25519.Ed25519PrivateKey, issuer_id: str):
        self.issuer_id = issuer_id
        payload = self.to_bytes()
        self.signature = issuer_key.sign(payload)

    def verify(self, issuer_public_key: ed25519.Ed25519PublicKey) -> bool:
        try:
            payload = self.to_bytes()
            issuer_public_key.verify(self.signature, payload)
            return True
        except:
            return False

class IdentityManager:
    """
    Manages Identities and Revocation Lists.
    """
    def __init__(self, storage_path: str = "pki_store"):
        self.storage_path = storage_path
        self.revocation_list: List[str] = []
        self.trusted_issuers: Dict[str, ed25519.Ed25519PublicKey] = {}
        
    def generate_hardware_id(self) -> str:
        # Simulate Hardware ID generation (e.g. from CPU serial)
        # In production, use platform-specific calls
        return hashlib.sha256(b"CPU_SERIAL_DISK_SERIAL").hexdigest()

    def create_identity(self, user_id: str) -> Tuple[ed25519.Ed25519PrivateKey, Certificate]:
        # Generate Ed25519 Key Pair
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Create Certificate
        cert = Certificate(
            user_id=user_id,
            public_key_bytes=pub_bytes,
            hardware_id=self.generate_hardware_id(),
            valid_until=int(time.time()) + 31536000 # 1 Year
        )
        
        # Self-sign for now (or sign with a root key if available)
        cert.sign(priv_key, user_id)
        
        return priv_key, cert

    def revoke_identity(self, user_id: str):
        self.revocation_list.append(user_id)
        # Publish revocation list...

    def is_valid(self, cert: Certificate) -> bool:
        if cert.user_id in self.revocation_list:
            return False
        if time.time() > cert.valid_until:
            return False
        # Verify signature...
        return True
