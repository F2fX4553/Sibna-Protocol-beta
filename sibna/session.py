import time
import logging
from typing import Optional
from sibna.ratchet import DoubleRatchet
from sibna.compression import compress, decompress

logger = logging.getLogger(__name__)

class SibnaSession:
    """
    Secure Session Manager using Double Ratchet.
    Provides forward secrecy and break-in recovery.
    """
    def __init__(self, shared_secret: bytes, peer_public_key: bytes = None, is_initiator: bool = True, enable_compression: bool = True):
        self.shared_secret = shared_secret
        self.enable_compression = enable_compression
        self.created_at = time.time()
        self.last_activity = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        
        # Initialize Ratchet
        # For the initial handshake, we assume the shared_secret is the ROOT KEY.
        # If peer_public_key is None, we use a dummy key to initialize, 
        # expecting the first message header to carry the real key or trigger an update.
        if peer_public_key is None:
             peer_public_key = b'\x00' * 32
             
        self.ratchet = DoubleRatchet(shared_secret, peer_public_key, is_initiator)

    def enc(self, plaintext: bytes) -> bytes:
        self.last_activity = time.time()
        
        if self.enable_compression:
            plaintext = compress(plaintext)
            
        # Ratchet Encrypt
        ciphertext = self.ratchet.encrypt(plaintext)
        
        self.bytes_sent += len(ciphertext)
        return ciphertext

    def dec(self, ciphertext: bytes) -> Optional[bytes]:
        self.last_activity = time.time()
        
        try:
            # Ratchet Decrypt
            plaintext = self.ratchet.decrypt(ciphertext)
            
            if self.enable_compression:
                plaintext = decompress(plaintext)
                
            self.bytes_received += len(ciphertext)
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    def secure_wipe(self):
        # In a real implementation, we would wipe the ratchet state
        # For now, we rely on Python's GC and the OS to clear memory eventually
        # or use the secure_wipe primitive on the keys if accessible.
        pass

__all__ = ['SibnaSession']
