# Export message type constants for tests
__all__ = [
    'DoubleRatchet',
    'MSG_TYPE_DATA',
    'MSG_TYPE_KEEPALIVE',
    'MSG_TYPE_REKEY',
]
import os
import hmac
import hashlib
from typing import Tuple, Optional, Set
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sibna.crypto import KeyExchange, MultiLayerEncryptor, secure_wipe

# Message Types (per whitepaper)
MSG_TYPE_DATA = 0x10
MSG_TYPE_KEEPALIVE = 0x11
MSG_TYPE_REKEY = 0x12

class DoubleRatchet:
    """
    Double Ratchet Algorithm Implementation (Signal Protocol).
    Provides forward secrecy and post-compromise security.
    """
    def __init__(self, shared_secret: bytes, peer_public_key: bytes, is_initiator: bool, key_pair: Optional[KeyExchange] = None):
        self.root_key = shared_secret
        self.key_exchange = key_pair if key_pair else KeyExchange()
        self.peer_public_key = peer_public_key
        self.is_initiator = is_initiator
        
        # Chain Keys
        self.send_chain_key: Optional[bytes] = None
        self.recv_chain_key: Optional[bytes] = None
        
        # Message Numbers
        self.send_n = 0
        self.recv_n = 0
        self.prev_send_n = 0
        
        # Anti-Replay
        self.received_message_ids: Set[Tuple[bytes, int]] = set()
        
        # Initialize based on role
        if is_initiator:
            # Alice: Initialize send chain only
            dh_out = self.key_exchange.exchange(peer_public_key)
            self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, dh_out)
        # Bob: Will initialize on first receive

    def _kdf_rk(self, rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        """KDF for Root Chain. Returns: (root_key, chain_key)"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rk,
            info=b'sibna-ratchet-root',  # Updated per whitepaper
        )
        derived = hkdf.derive(dh_out)
        return derived[:32], derived[32:]

    def _kdf_ck(self, ck: bytes) -> Tuple[bytes, bytes]:
        """KDF for Chain Key. Returns: (chain_key, message_key)"""
        mk = hmac.new(ck, b'\x01', hashlib.sha256).digest()
        next_ck = hmac.new(ck, b'\x02', hashlib.sha256).digest()
        return next_ck, mk

    def _ratchet_diffie_hellman(self, peer_public_key: bytes):
        """Perform a DH ratchet step"""
        self.prev_send_n = self.send_n
        self.send_n = 0
        self.recv_n = 0
        self.peer_public_key = peer_public_key
        
        # Receive chain
        dh_out = self.key_exchange.exchange(peer_public_key)
        self.root_key, self.recv_chain_key = self._kdf_rk(self.root_key, dh_out)
        
        # Generate new key pair
        self.key_exchange = KeyExchange()
        
        # Send chain
        dh_out = self.key_exchange.exchange(peer_public_key)
        self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, dh_out)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a message per whitepaper specification.
        
        Message Format (61 bytes header + ciphertext):
        - Type: 1 byte (0x10 for DATA)
        - DH Public Key: 32 bytes
        - Previous N: 4 bytes
        - Message Number: 4 bytes
        - Payload Length: 4 bytes
        - Encrypted Payload: variable
        - Poly1305 Tag: 16 bytes (included in ciphertext)
        
        Total header: 45 bytes (before encryption)
        Total with tag: 61 bytes minimum
        """
        # Enforce Responder Receive-Before-Send
        if not self.is_initiator and self.recv_chain_key is None:
             raise RuntimeError("Responder cannot send message before receiving first message from Initiator.")

        # If send_chain_key is None, derive it (responder's first send)
        if self.send_chain_key is None:
            # Responder: derive send chain using current key pair
            dh_out = self.key_exchange.exchange(self.peer_public_key)
            self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, dh_out)
        
        # Step send chain
        self.send_chain_key, message_key = self._kdf_ck(self.send_chain_key)
        
        # Encrypt
        # Use bytearray for key to allow wiping
        message_key_ba = bytearray(message_key)
        try:
            encryptor = MultiLayerEncryptor(message_key_ba)
            
            # Build header per whitepaper (45 bytes)
            header = (
                bytes([MSG_TYPE_DATA]) +                      # 1 byte
                self.key_exchange.get_public_bytes() +        # 32 bytes
                self.prev_send_n.to_bytes(4, 'big') +         # 4 bytes
                self.send_n.to_bytes(4, 'big') +              # 4 bytes
                len(plaintext).to_bytes(4, 'big')             # 4 bytes
            )
            
            # Encrypt with header as associated data
            ciphertext = encryptor.encrypt(plaintext, associated_data=header)
            self.send_n += 1
            
            # Return: header (45) + ciphertext (len(plaintext) + overhead)
            return header + ciphertext
        finally:
            secure_wipe(message_key_ba)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt a message per whitepaper specification.
        
        Expects: Header (45 bytes) + Ciphertext
        """
        # Minimum: 45 header + 16 tag
        if len(data) < 61:
            raise ValueError(f"Message too short: {len(data)} < 61 bytes")
            
        # Parse header (45 bytes)
        msg_type = data[0]
        if msg_type != MSG_TYPE_DATA:
            raise ValueError(f"Invalid message type: {msg_type:#x} (expected {MSG_TYPE_DATA:#x})")
        
        peer_pk = data[1:33]
        pn = int.from_bytes(data[33:37], 'big')
        n = int.from_bytes(data[37:41], 'big')
        payload_len = int.from_bytes(data[41:45], 'big')
        
        header = data[:45]
        ciphertext = data[45:]
        
        # Verify payload length matches
        # ciphertext should be: payload_len + overhead (from MultiLayerEncryptor)
        # MultiLayerEncryptor adds: 32 (HMAC) + 12 (nonce_outer) + 16 (AES tag) + 12 (nonce_inner) + 16 (ChaCha tag)
        expected_ct_len = payload_len + 32 + 12 + 16 + 12 + 16  # 88 bytes overhead
        if len(ciphertext) != expected_ct_len:
            raise ValueError(
                f"Payload length mismatch: got {len(ciphertext)}, "
                f"expected {expected_ct_len} (payload={payload_len} + 88 overhead)"
            )
        
        # Anti-Replay Check
        msg_id = (peer_pk, n)
        if msg_id in self.received_message_ids:
            raise ValueError(f"Replay detected: Message {n} with this key already processed.")
        
        # Check if DH Ratchet is needed
        if peer_pk != self.peer_public_key:
            # Skip any missed messages from previous chain
            while self.recv_n < pn:
                self.recv_chain_key, _ = self._kdf_ck(self.recv_chain_key)
                self.recv_n += 1
            
            # Peer has ratcheted - perform DH ratchet
            self._ratchet_diffie_hellman(peer_pk)
        elif self.recv_chain_key is None:
            # First message for responder
            dh_out = self.key_exchange.exchange(peer_pk)
            self.root_key, self.recv_chain_key = self._kdf_rk(self.root_key, dh_out)
            
        # Skip to message number n
        while self.recv_n < n:
            self.recv_chain_key, _ = self._kdf_ck(self.recv_chain_key)
            self.recv_n += 1
             
        # Derive message key
        self.recv_chain_key, message_key = self._kdf_ck(self.recv_chain_key)
        self.recv_n += 1
        
        # Decrypt
        message_key_ba = bytearray(message_key)
        try:
            encryptor = MultiLayerEncryptor(message_key_ba)
            plaintext = encryptor.decrypt(ciphertext, associated_data=header)
            
            # Verify decrypted payload length
            if len(plaintext) != payload_len:
                raise ValueError(
                    f"Decrypted payload length mismatch: got {len(plaintext)}, expected {payload_len}"
                )
            
            # Mark as received only after successful decryption
            self.received_message_ids.add(msg_id)
            
            return plaintext
        finally:
            secure_wipe(message_key_ba)

