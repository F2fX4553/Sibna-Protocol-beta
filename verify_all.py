#!/usr/bin/env python3
"""
Quick verification script to test all Obsidian Sovereign components
"""
import sys
import os

def test_compression():
    """Test compression module"""
    from sibna.compression import compress, decompress
    data = b'Test data ' * 100
    compressed = compress(data)
    decompressed = decompress(compressed)
    assert data == decompressed, "Compression/decompression failed"
    print("✅ Compression: PASSED")
    return True

def test_encryption():
    """Test multi-layer encryption"""
    from sibna.crypto import MultiLayerEncryptor
    key = os.urandom(32)
    enc = MultiLayerEncryptor(key)
    plaintext = b'Secret message'
    ciphertext = enc.encrypt(plaintext)
    decrypted = enc.decrypt(ciphertext)
    assert plaintext == decrypted, "Encryption/decryption failed"
    print("✅ Encryption: PASSED")
    return True

def test_key_exchange():
    """Test X25519 key exchange"""
    from sibna.crypto import KeyExchange
    alice = KeyExchange()
    bob = KeyExchange()
    alice_shared = alice.exchange(bob.get_public_bytes())
    bob_shared = bob.exchange(alice.get_public_bytes())
    assert alice_shared == bob_shared, "Key exchange failed"
    print("✅ Key Exchange: PASSED")
    return True

def test_double_ratchet():
    """Test Double Ratchet bidirectional communication"""
    from sibna.ratchet import DoubleRatchet
    from sibna.crypto import KeyExchange
    
    shared_secret = os.urandom(32)
    bob_keys = KeyExchange()
    
    alice = DoubleRatchet(shared_secret, bob_keys.get_public_bytes(), True)
    bob = DoubleRatchet(shared_secret, alice.key_exchange.get_public_bytes(), False, bob_keys)
    
    # Alice -> Bob
    msg1 = b'Hello from Alice'
    enc1 = alice.encrypt(msg1)
    dec1 = bob.decrypt(enc1)
    assert dec1 == msg1, "Alice->Bob failed"
    
    # Bob -> Alice
    msg2 = b'Hello from Bob'
    enc2 = bob.encrypt(msg2)
    dec2 = alice.decrypt(enc2)
    assert dec2 == msg2, "Bob->Alice failed"
    
    # Alice -> Bob (2nd message)
    msg3 = b'Alice again'
    enc3 = alice.encrypt(msg3)
    dec3 = bob.decrypt(enc3)
    assert dec3 == msg3, "Alice->Bob (2nd) failed"
    
    print("✅ Double Ratchet: PASSED")
    return True

def test_pki():
    """Test PKI certificate generation"""
    from sibna.pki import IdentityManager
    pki = IdentityManager()
    priv_key, cert = pki.create_identity('test_user')
    # Just verify it was created
    assert cert is not None, "Certificate creation failed"
    print("✅ PKI: PASSED")
    return True

def main():
    print("=" * 60)
    print("OBSIDIAN SOVEREIGN - COMPONENT VERIFICATION")
    print("=" * 60)
    print()
    
    tests = [
        ("Compression", test_compression),
        ("Encryption", test_encryption),
        ("Key Exchange", test_key_exchange),
        ("Double Ratchet", test_double_ratchet),
        ("PKI", test_pki),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {name}: FAILED - {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
