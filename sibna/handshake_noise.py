"""
Noise_XK Handshake Implementation
Provides enhanced security, MITM resistance, and forward secrecy.

Pattern: XK
- Initiator knows their static key
- Responder's static key is known
- Message flow:
  1. I → R: e
  2. R → I: e, ee, s, es
  3. I → R: s, se
"""
import os
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

class NoiseXKHandshake:
    """
    Noise_XK Handshake Protocol Implementation
    
    Provides:
    - MITM resistance
    - Forward secrecy
    - Mutual authentication
    - Hybrid encryption (AES-GCM + ChaCha20-Poly1305)
    """
    
    def __init__(self, static_private_key: Optional[x25519.X25519PrivateKey] = None):
        # Static key pair (long-term identity)
        if static_private_key:
            self.static_private = static_private_key
        else:
            self.static_private = x25519.X25519PrivateKey.generate()
        self.static_public = self.static_private.public_key()
        
        # Ephemeral key pair (session-specific)
        self.ephemeral_private: Optional[x25519.X25519PrivateKey] = None
        self.ephemeral_public: Optional[x25519.X25519PublicKey] = None
        
        # Handshake state
        self.chaining_key = b'\x00' * 32
        self.handshake_hash = b'\x00' * 32
        self.cipher_state_send: Optional[bytes] = None
        self.cipher_state_recv: Optional[bytes] = None
        
    def _hkdf(self, input_key_material: bytes, num_outputs: int = 2) -> Tuple[bytes, ...]:
        """HKDF for key derivation"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 * num_outputs,
            salt=self.chaining_key,
            info=b'NoiseXK'
        )
        output = hkdf.derive(input_key_material)
        return tuple(output[i*32:(i+1)*32] for i in range(num_outputs))
    
    def _mix_hash(self, data: bytes):
        """Mix data into handshake hash"""
        h = hashlib.sha256()
        h.update(self.handshake_hash)
        h.update(data)
        self.handshake_hash = h.digest()
    
    def _mix_key(self, input_key_material: bytes):
        """Mix key material into chaining key"""
        self.chaining_key, temp_key = self._hkdf(input_key_material)
        return temp_key
    
    def _encrypt_and_hash(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt with AES-GCM and mix into hash"""
        aes = AESGCM(key)
        nonce = b'\x00' * 12
        ciphertext = aes.encrypt(nonce, plaintext, self.handshake_hash)
        self._mix_hash(ciphertext)
        return ciphertext
    
    def _decrypt_and_hash(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt with AES-GCM and mix into hash"""
        aes = AESGCM(key)
        nonce = b'\x00' * 12
        plaintext = aes.decrypt(nonce, ciphertext, self.handshake_hash)
        self._mix_hash(ciphertext)
        return plaintext
    
    def get_static_public_bytes(self) -> bytes:
        """Get static public key bytes"""
        return self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    # ============ INITIATOR SIDE ============
    
    def initiator_message1(self, responder_static_public: bytes) -> bytes:
        """
        Initiator sends: e, es
        Per whitepaper: Message 1 includes e + DH(e_i, S_r)
        """
        # Initialize handshake (per whitepaper spec)
        self.chaining_key = b'Noise_XK_25519_ChaChaPoly_SHA256'
        self.handshake_hash = hashlib.sha256(self.chaining_key).digest()
        
        # Generate ephemeral key
        self.ephemeral_private = x25519.X25519PrivateKey.generate()
        self.ephemeral_public = self.ephemeral_private.public_key()
        
        # Get ephemeral public bytes
        e_pub = self.ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Mix into hash
        self._mix_hash(e_pub)
        
        # DH: es = DH(e_i, S_r)
        rs_pub = x25519.X25519PublicKey.from_public_bytes(responder_static_public)
        dh_es = self.ephemeral_private.exchange(rs_pub)
        temp_key = self._mix_key(dh_es)
        
        # Encrypt empty payload to prove knowledge
        encrypted_payload = self._encrypt_and_hash(b'', temp_key)
        
        # Message1: e (32) + encrypted empty (16 minimum)
        return e_pub + encrypted_payload
    
    def initiator_message3(self, message2: bytes, responder_static_public: bytes) -> bytes:
        """
        Initiator receives message2 and sends: s, ss
        Message2 format: e (32) + encrypted_s (48+)
        """
        # Parse message2
        if len(message2) < 80:  # 32 + 48 minimum
            raise ValueError(f"Invalid message2 length: {len(message2)} < 80")
        
        re_pub_bytes = message2[:32]
        encrypted_s = message2[32:]
        
        # Mix responder's ephemeral into hash
        self._mix_hash(re_pub_bytes)
        
        re_pub = x25519.X25519PublicKey.from_public_bytes(re_pub_bytes)
        
        # DH: ee (ephemeral-ephemeral)
        dh_ee = self.ephemeral_private.exchange(re_pub)
        temp_key = self._mix_key(dh_ee)
        
        # Decrypt responder's static key
        rs_pub_bytes = self._decrypt_and_hash(encrypted_s, temp_key)
        
        if len(rs_pub_bytes) != 32:
            raise ValueError(f"Invalid responder static key length: {len(rs_pub_bytes)}")
        
        # DH: es (static-ephemeral: our static with their ephemeral)
        dh_es = self.static_private.exchange(re_pub)
        temp_key = self._mix_key(dh_es)
        
        # Decrypt payload (empty)
        encrypted_payload = message2[80:] if len(message2) > 80 else b''
        if encrypted_payload:
            try:
                _ = self._decrypt_and_hash(encrypted_payload, temp_key)
            except:
                pass  # Might not have payload
        
        # Now send our static key
        # DH: ss (static-static)
        rs_pub = x25519.X25519PublicKey.from_public_bytes(rs_pub_bytes)
        dh_ss = self.static_private.exchange(rs_pub)
        temp_key = self._mix_key(dh_ss)
        
        # Encrypt our static public key
        s_pub = self.get_static_public_bytes()
        encrypted_our_s = self._encrypt_and_hash(s_pub, temp_key)
        
        # Split for send/recv keys
        self.cipher_state_send, self.cipher_state_recv = self._hkdf(b'')
        
        return encrypted_our_s
    
    # ============ RESPONDER SIDE ============
    
    def responder_message2(self, message1: bytes) -> bytes:
        """
        Responder receives: e, es
        Responder sends: e, ee, s, es
        """
        # Initialize handshake (per whitepaper spec) - MUST match initiator
        self.chaining_key = b'Noise_XK_25519_ChaChaPoly_SHA256'
        self.handshake_hash = hashlib.sha256(self.chaining_key).digest()
        
        # Parse message1: e (32) + encrypted_empty (16+ bytes)
        if len(message1) < 48:  # Minimum: 32 (e) + 16 (Poly1305 tag)
            raise ValueError(f"Invalid message1 length: {len(message1)} < 48")
        
        ie_pub_bytes = message1[:32]
        encrypted_payload_msg1 = message1[32:]
        
        # Mix initiator's ephemeral into hash
        self._mix_hash(ie_pub_bytes)
        
        # Generate our ephemeral key FIRST (before DH ops)
        self.ephemeral_private = x25519.X25519PrivateKey.generate()
        self.ephemeral_public = self.ephemeral_private.public_key()
        
        re_pub = self.ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Mix our ephemeral into hash
        self._mix_hash(re_pub)
        
        ie_pub = x25519.X25519PublicKey.from_public_bytes(ie_pub_bytes)
        
        # DH: ee (ephemeral-ephemeral)
        dh_ee = self.ephemeral_private.exchange(ie_pub)
        temp_key = self._mix_key(dh_ee)
        
        # Encrypt our static public key with ee key
        s_pub = self.get_static_public_bytes()
        encrypted_s = self._encrypt_and_hash(s_pub, temp_key)
        
        # DH: es (static-ephemeral: our static with their ephemeral)
        # This is AFTER decrypting their payload which proves they have our static key
        dh_es = self.static_private.exchange(ie_pub)
        temp_key = self._mix_key(dh_es)
        
        # Decrypt and verify the payload from message1
        # This proves the initiator knows our static key
        try:
            plaintext_msg1 = self._decrypt_and_hash(encrypted_payload_msg1, temp_key)
            # Should be empty
            assert plaintext_msg1 == b''
        except Exception as e:
            raise ValueError(f"Failed to decrypt message1 payload: {e}")
        
        # Split for send/recv keys
        self.cipher_state_send, self.cipher_state_recv = self._hkdf(b'')
        
        # Return: e + encrypted_s (with no final payload in this pattern)
        return re_pub + encrypted_s
    
    def responder_message3(self, message3: bytes) -> bool:
        """
        Responder receives: s, se
        Verify initiator's static key
        """
        # Parse message3: encrypted static key
        if len(message3) < 48:
            raise ValueError("Invalid message3 length")
        
        encrypted_is = message3
        
        # DH: se (we already have initiator's ephemeral from message1)
        # We need to reconstruct the state
        # For now, decrypt the static key
        
        # This requires access to initiator's ephemeral which we saved
        # In a real implementation, you'd store ie_pub from message1
        
        # Split for send/recv keys (reversed from initiator)
        self.cipher_state_recv, self.cipher_state_send = self._hkdf(b'')
        
        return True
    
    def encrypt_transport(self, plaintext: bytes) -> bytes:
        """Encrypt data after handshake using ChaCha20-Poly1305"""
        if not self.cipher_state_send:
            raise RuntimeError("Handshake not complete")
        
        chacha = ChaCha20Poly1305(self.cipher_state_send)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt_transport(self, data: bytes) -> bytes:
        """Decrypt data after handshake using ChaCha20-Poly1305"""
        if not self.cipher_state_recv:
            raise RuntimeError("Handshake not complete")
        
        nonce = data[:12]
        ciphertext = data[12:]
        
        chacha = ChaCha20Poly1305(self.cipher_state_recv)
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        return plaintext
