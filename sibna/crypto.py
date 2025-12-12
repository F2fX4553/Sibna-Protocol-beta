import os
import logging
import platform
import ctypes
import hmac
from typing import Optional, Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature, InvalidTag
import hashlib

# Setup logging
logger = logging.getLogger(__name__)

# --------------------------
# Native Library Loading
# --------------------------
def get_lib_path() -> str:
    if platform.system() == "Windows":
        lib_name = "obsidian_engine.dll"
    else:
        lib_name = "obsidian_engine.so"
    return os.path.join(os.path.dirname(__file__), lib_name)

_c_lib: Optional[ctypes.CDLL] = None
try:
    lib_path = get_lib_path()
    if os.path.exists(lib_path):
        _c_lib = ctypes.CDLL(lib_path)
        # Define signatures
        _c_lib.secure_wipe.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _c_lib.lock_memory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _c_lib.unlock_memory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
except Exception as e:
    logger.warning(f"Native library not loaded: {e}")

# --------------------------
# Memory Protection
# --------------------------
def secure_wipe(data: Union[bytes, bytearray, ctypes.Array]):
    """
    Securely wipe memory using native implementation or DoD 5220.22-M standard fallback.
    """
    if _c_lib:
        # Use native C implementation if available
        if isinstance(data, (bytes, bytearray)):
            if isinstance(data, bytearray):
                ctx = (ctypes.c_char * len(data)).from_buffer(data)
                _c_lib.secure_wipe(ctx, len(data))
        elif isinstance(data, ctypes.Array):
            _c_lib.secure_wipe(data, ctypes.sizeof(data))
    else:
        # Enhanced Python fallback - DoD 5220.22-M standard (3-pass)
        if isinstance(data, bytearray):
            length = len(data)
            
            # Pass 1: Write zeros
            try:
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, length)
            except Exception:
                for i in range(length):
                    data[i] = 0
            
            # Pass 2: Write 0xFF
            try:
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0xFF, length)
            except Exception:
                for i in range(length):
                    data[i] = 0xFF
            
            # Pass 3: Write random data then zero again
            try:
                import os
                random_data = os.urandom(length)
                for i in range(length):
                    data[i] = random_data[i]
                
                # Final zeroing
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, length)
            except Exception:
                for i in range(length):
                    data[i] = 0
        
        elif isinstance(data, bytes):
            logger.warning("Cannot securely wipe immutable bytes object - use bytearray instead")

# --------------------------
# Key Exchange (X25519)
# --------------------------
class KeyExchange:
    def __init__(self, private_key: Optional[x25519.X25519PrivateKey] = None):
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret

# --------------------------
# Signatures (Ed25519)
# --------------------------
class Signer:
    def __init__(self, private_key_bytes: Optional[bytes] = None):
        if private_key_bytes:
            self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    @staticmethod
    def verify(public_bytes: bytes, signature: bytes, data: bytes) -> None:
        if len(public_bytes) != 32:
            raise ValueError(f"Invalid public key length: {len(public_bytes)} (expected 32)")
        if len(signature) != 64:
            raise ValueError(f"Invalid signature length: {len(signature)} (expected 64)")
        if not data:
            raise ValueError("Data cannot be empty")
        
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, data)

# --------------------------
# Multi-Layer Encryption
# --------------------------
class MultiLayerEncryptor:
    """
    Implements ChaCha20-Poly1305 + AES-256-GCM + HMAC-SHA256
    """
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
            
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96, # 32 * 3
            salt=None,
            info=b'obsidian-multilayer',
        )
        derived = hkdf.derive(key)
        self.key_layer1 = derived[:32] # Outer (AES)
        self.key_layer2 = derived[32:64] # Inner (ChaCha)
        self.key_hmac = derived[64:] # HMAC
        
        self.aes = AESGCM(self.key_layer1)
        self.chacha = ChaCha20Poly1305(self.key_layer2)

    def encrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        nonce_inner = os.urandom(12)
        ciphertext_inner = self.chacha.encrypt(nonce_inner, data, associated_data)
        
        nonce_outer = os.urandom(12)
        payload = nonce_inner + ciphertext_inner
        ciphertext_outer = self.aes.encrypt(nonce_outer, payload, associated_data)
        
        combined_ct = nonce_outer + ciphertext_outer
        h = hmac.new(self.key_hmac, combined_ct, hashlib.sha256)
        if associated_data:
            h.update(associated_data)
        mac = h.digest()
        
        return mac + combined_ct

    def decrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        if len(data) < 60:
            raise ValueError("Data too short")
            
        mac = data[:32]
        combined_ct = data[32:]
        
        h = hmac.new(self.key_hmac, combined_ct, hashlib.sha256)
        if associated_data:
            h.update(associated_data)
        
        if not hmac.compare_digest(h.digest(), mac):
            raise InvalidSignature("HMAC verification failed - Integrity Compromised")
            
        nonce_outer = combined_ct[:12]
        ciphertext_outer = combined_ct[12:]
        
        try:
            payload = self.aes.decrypt(nonce_outer, ciphertext_outer, associated_data)
        except InvalidTag:
            raise ValueError("Outer layer decryption failed")
            
        if len(payload) < 28:
            raise ValueError("Inner payload too short")
            
        nonce_inner = payload[:12]
        ciphertext_inner = payload[12:]
        
        try:
            plaintext = self.chacha.decrypt(nonce_inner, ciphertext_inner, associated_data)
        except InvalidTag:
            raise ValueError("Inner layer decryption failed")
            
        return plaintext

    def secure_wipe(self):
        secure_wipe(bytearray(self.key))

def get_crypto_status() -> dict:
    """
    Get status of crypto engine
    """
    return {
        'native_library_loaded': _c_lib is not None,
        'using_fallback': _c_lib is None,
        'fallback_available': True,
        'library_path': get_lib_path(),
        'library_exists': os.path.exists(get_lib_path()),
        'secure_wipe_available': _c_lib is not None
    }

__all__ = ['MultiLayerEncryptor', 'KeyExchange', 'Signer', 'secure_wipe', 'Core', 'get_crypto_status']
