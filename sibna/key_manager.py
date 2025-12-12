import os
import json
import secrets
import time
import logging
import base64
from typing import Dict, Optional, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from .crypto import Signer, secure_wipe

logger = logging.getLogger(__name__)

class SecureKeyManager:
    def __init__(self, config_path: Optional[str] = None):
        """
        Advanced Secure Key Manager
        - AES-256-GCM for storage
        - Ed25519 for Identity
        - Automatic Rotation
        """
        self.config_path = config_path or os.environ.get(
            "OBSIDIAN_KEYS_PATH",
            os.path.join(os.getcwd(), "obsidian_keys.json")
        )
        self.master_key: Optional[bytes] = None
        self.identity_key: Optional[Signer] = None
        self.session_keys: Dict[str, Dict] = {}
        self.key_rotation_interval = 3600 # 1 hour
        self.last_rotation = time.time()
        
        dirname = os.path.dirname(self.config_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
    
    def generate_master_key(self, password: Optional[str] = None) -> bytes:
        """Generate a new master key (AES-256)"""
        if password:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000, # Increased iterations
            )
            self.master_key = kdf.derive(password.encode())
            self._salt = salt # Need to store salt if we were persisting it, but for now we assume memory or re-derivation
        else:
            self.master_key = AESGCM.generate_key(bit_length=256)
        
        # Generate Identity Key if not exists
        if not self.identity_key:
            self.identity_key = Signer()
            
        self._save_keys()
        logger.info("✅ Master key & Identity generated successfully")
        return self.master_key
    
    def load_or_create_keys(self, password: Optional[str] = None) -> bool:
        """Load keys from encrypted storage"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'rb') as f:
                    data = f.read()
                
                # Format: nonce(12) + salt(16) + ciphertext
                nonce = data[:12]
                salt = data[12:28]
                ciphertext = data[28:]
                
                if password:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=600000,
                    )
                    self.master_key = kdf.derive(password.encode())
                elif not self.master_key:
                    logger.error("❌ Master key or password required to decrypt")
                    return False
                    
                aes = AESGCM(self.master_key)
                try:
                    plaintext = aes.decrypt(nonce, ciphertext, None)
                    keys_data = json.loads(plaintext.decode())
                    
                    self.session_keys = keys_data.get('session_keys', {})
                    self.last_rotation = keys_data.get('last_rotation', time.time())
                    
                    # Load Identity Key
                    id_bytes_b64 = keys_data.get('identity_private_key')
                    if id_bytes_b64:
                        self.identity_key = Signer(base64.b64decode(id_bytes_b64))
                    else:
                        self.identity_key = Signer()
                        
                    logger.info("✅ Keys loaded successfully")
                    return True
                except Exception as e:
                    logger.error(f"❌ Decryption failed: {e}")
                    return False
            
            logger.info("🆕 No existing keys found, generating new ones")
            self.generate_master_key(password)
            return True
            
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            return False
    
    def _save_keys(self) -> bool:
        """Save keys encrypted with AES-256-GCM"""
        try:
            if not self.master_key: return False
            
            keys_data = {
                'session_keys': self.session_keys,
                'last_rotation': self.last_rotation,
                'created_at': time.time(),
                'identity_private_key': base64.b64encode(
                    self.identity_key.private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                ).decode() if self.identity_key else None,
                'version': '2.0'
            }
            
            aes = AESGCM(self.master_key)
            nonce = os.urandom(12)
            salt = getattr(self, '_salt', os.urandom(16))
            
            ciphertext = aes.encrypt(nonce, json.dumps(keys_data).encode(), None)
            
            # Atomic write
            temp_path = self.config_path + ".tmp"
            with open(temp_path, 'wb') as f:
                f.write(nonce + salt + ciphertext)
            
            if os.path.exists(self.config_path):
                os.replace(temp_path, self.config_path)
            else:
                os.rename(temp_path, self.config_path)
                
            logger.info("💾 Keys saved securely")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save keys: {e}")
            return False

    def get_identity_public_key(self) -> bytes:
        if not self.identity_key:
            raise ValueError("Identity key not initialized")
        return self.identity_key.get_public_bytes()

    def sign_data(self, data: bytes) -> bytes:
        if not self.identity_key:
            raise ValueError("Identity key not initialized")
        return self.identity_key.sign(data)

    def generate_session_key(self, session_id: str) -> str:
        """Generate a new 32-byte session key"""
        key_material = secrets.token_bytes(32)
        key_id = secrets.token_hex(8)
        
        self.session_keys[key_id] = {
            'key': base64.b64encode(key_material).decode(),
            'created_at': time.time(),
            'session_id': session_id,
            'usage_count': 0,
            'last_used': time.time()
        }
        
        self._save_keys()
        return key_id
    
    def get_session_key(self, key_id: str) -> Optional[bytes]:
        if key_id in self.session_keys:
            key_data = self.session_keys[key_id]
            key_data['usage_count'] += 1
            key_data['last_used'] = time.time()
            # Don't save on every read to avoid IO thrashing, maybe throttle
            return base64.b64decode(key_data['key'])
        return None

    def rotate_keys_if_needed(self) -> bool:
        current_time = time.time()
        if current_time - self.last_rotation > self.key_rotation_interval:
            logger.info("🔄 Rotating keys...")
            
            # Expire old keys
            active_keys = {}
            for kid, kdata in self.session_keys.items():
                if current_time - kdata['created_at'] < (self.key_rotation_interval * 2):
                    active_keys[kid] = kdata
            
            self.session_keys = active_keys
            self.last_rotation = current_time
            self._save_keys()
            return True
        return False

    def secure_wipe(self):
        """Zeroize keys in memory"""
        if self.master_key:
            secure_wipe(bytearray(self.master_key))
            self.master_key = None
        self.session_keys.clear()
        self.identity_key = None

default_key_manager = SecureKeyManager()