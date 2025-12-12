# Sibna Protocol - Usage Examples

## Table of Contents
- [Basic Secure Messaging](#basic-secure-messaging)
- [Multi-Layer Encryption](#multi-layer-encryption)
- [Noise_XK Handshake](#noise_xk-handshake)
- [Double Ratchet Messaging](#double-ratchet-messaging)
- [Audit Logging](#audit-logging)
- [Secure Memory Handling](#secure-memory-handling)

---

## Basic Secure Messaging

```python
from sibna.handshake import SecureHandshake
from sibna.key_manager import SecureKeyManager
from sibna.ratchet import DoubleRatchet

# Initialize key managers
alice_km = SecureKeyManager()
alice_km.generate_master_key()

bob_km = SecureKeyManager()
bob_km.generate_master_key()

# Perform handshake
alice_hs = SecureHandshake(alice_km)
bob_hs = SecureHandshake(bob_km)

# 1. ClientHello
client_hello = alice_hs.create_client_hello()

# 2. ServerHello
server_hello, shared_secret = bob_hs.process_client_hello(client_hello)

# 3. Client processes ServerHello
alice_secret = alice_hs.process_server_hello(client_hello, server_hello)

# 4. ClientFinished
client_finished = alice_hs.create_client_finished(server_hello, alice_secret)
bob_hs.process_client_finished(server_hello, client_finished)

# Now use Double Ratchet for messaging
alice_ratchet = DoubleRatchet(
    alice_secret,
    bob_hs.ephemeral_key.get_public_bytes(),
    is_initiator=True
)

bob_ratchet = DoubleRatchet(
    shared_secret,
    alice_hs.ephemeral_key.get_public_bytes(),
    is_initiator=False
)

# Send encrypted messages
message = b"Hello, secure world!"
encrypted = alice_ratchet.encrypt(message)
decrypted = bob_ratchet.decrypt(encrypted)

print(f"Original: {message}")
print(f"Decrypted: {decrypted}")
```

---

## Multi-Layer Encryption

```python
from sibna.crypto import MultiLayerEncryptor
import os

# Generate a key
key = os.urandom(32)

# Create encryptor
encryptor = MultiLayerEncryptor(key)

# Encrypt with associated data
plaintext = b"Sensitive information"
metadata = b"user_id:12345"

ciphertext = encryptor.encrypt(plaintext, associated_data=metadata)
print(f"Ciphertext size: {len(ciphertext)} bytes")

# Decrypt data
decrypted = encryptor.decrypt(ciphertext, associated_data=metadata)

assert decrypted == plaintext
print("✅ Multi-layer encryption successful!")

# The encryption layers:
# 1. ChaCha20-Poly1305 (inner layer)
# 2. AES-256-GCM (outer layer)
# 3. HMAC-SHA256 (integrity)
```

---

## Noise_XK Handshake

```python
from sibna.handshake_noise import NoiseXKHandshake
from cryptography.hazmat.primitives import serialization

# Alice (Initiator)
alice = NoiseXKHandshake()

# Bob (Responder)
bob = NoiseXKHandshake()
bob_static_public = bob.get_static_public_bytes()

# Message 1: Alice -> Bob (e, es)
# Per whitepaper: includes ephemeral key + DH with Bob's static key
msg1 = alice.initiator_message1(bob_static_public)
print(f"Message 1 size: {len(msg1)} bytes")  # 32 (e) + 16+ (encrypted payload)

# Message 2: Bob -> Alice (e, ee, s, es)
msg2 = bob.responder_message2(msg1)
print(f"Message 2 size: {len(msg2)} bytes")

# Message 3: Alice -> Bob (s, se)
msg3 = alice.initiator_message3(msg2, bob_static_public)
print(f"Message 3 size: {len(msg3)} bytes")

# Complete handshake on Bob's side
bob.responder_message3(msg3)

# Both parties now have transport keys
print("✅ Noise_XK handshake complete!")

# Use transport encryption
plaintext = b"Hello via Noise_XK!"
encrypted = alice.encrypt_transport(plaintext)
decrypted = bob.decrypt_transport(encrypted)

assert decrypted == plaintext
print("✅ Transport encryption working!")
```

---

## Double Ratchet Messaging

```python
from sibna.ratchet import DoubleRatchet, MSG_TYPE_DATA
from sibna.crypto import KeyExchange

# Setup
shared_secret = b'0' * 32

alice_kex = KeyExchange()
bob_kex = KeyExchange()

alice = DoubleRatchet(
    shared_secret,
    bob_kex.get_public_bytes(),
    is_initiator=True,
    key_pair=alice_kex
)

bob = DoubleRatchet(
    shared_secret,
    alice_kex.get_public_bytes(),
    is_initiator=False,
    key_pair=bob_kex
)

# Alice sends messages
for i in range(5):
    plaintext = f"Message {i} from Alice".encode()
    ciphertext = alice.encrypt(plaintext)
    
    # Verify message format (per whitepaper)
    assert ciphertext[0] == MSG_TYPE_DATA  # Type byte
    assert len(ciphertext) >= 61  # 45 header + 16 minimum tag
    
    # Bob decrypts
    decrypted = bob.decrypt(ciphertext)
    assert decrypted == plaintext
    print(f"✅ Message {i}: {decrypted.decode()}")

# Bob responds
response = b"Got all your messages!"
encrypted_response = bob.encrypt(response)
decrypted_response = alice.decrypt(encrypted_response)

print(f"✅ Bob's response: {decrypted_response.decode()}")

# Message format (per whitepaper Section 6.3.1):
# - Type: 1 byte (0x10 for DATA)
# - DH Public Key: 32 bytes
# - Previous N: 4 bytes
# - Message Number: 4 bytes
# - Payload Length: 4 bytes
# - Encrypted Payload: variable
# Total header: 45 bytes
```

---

## Audit Logging

```python
from sibna.audit_logger import AuditLogger

# Create logger
logger = AuditLogger(log_file="app_audit.log")

# Log events
logger.log_auth_attempt("user123", success=True)
logger.log_key_rotation({"rotated_keys": 5})
logger.log_security_incident("BRUTE_FORCE", {"attempts": 100})

# Verify integrity
if logger.verify_chain():
    print("✅ Audit log integrity verified")
else:
    print("❌ Audit log has been tampered with!")
```

---

## Secure Memory Handling

```python
from sibna.crypto import secure_wipe

# Use bytearray for sensitive data
sensitive_key = bytearray(b"my-secret-key-12345")

# ... use the key ...

# Securely wipe from memory (3-pass DoD 5220.22-M standard)
secure_wipe(sensitive_key)

# Key is now zeroed
assert all(b == 0 for b in sensitive_key)
print("✅ Sensitive data securely wiped!")
```

---

## Testing

Run the test suite:

```bash
# All tests
pytest tests/ -v

# Specific tests
pytest tests/test_handshake_compliance.py -v
pytest tests/test_message_format.py -v
```

---

## Protocol Compliance

All examples follow the **Sibna Protocol Whitepaper** specifications:
- ✅ Noise_XK handshake (Section 5.1)
- ✅ Double Ratchet (Section 5.3)
- ✅ Message format (Section 6.3)
- ✅ Cryptographic primitives (Section 4)
- ✅ Security requirements (Section 11)

---

**For more information, see [README.md](README.md) and [WHITEPAPER_FORMAL.md](WHITEPAPER_FORMAL.md)**
