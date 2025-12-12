"""
Comprehensive Functional Tests for Obsidian Sovereign
"""
import pytest
import os
from sibna.handshake import SecureHandshake
from sibna.key_manager import SecureKeyManager
from sibna.ratchet import DoubleRatchet
from sibna.crypto import MultiLayerEncryptor, secure_wipe
from sibna.audit_logger import AuditLogger

from sibna.crypto import KeyExchange
class TestHandshake:
    def test_full_handshake(self):
        """Test complete handshake flow using X25519 DH only (no PQC)"""
        # Setup
        alice_km = SecureKeyManager()
        alice_km.generate_master_key()
        bob_km = SecureKeyManager()
        bob_km.generate_master_key()
        
        alice = SecureHandshake(alice_km)
        bob = SecureHandshake(bob_km)
        
        # ClientHello
        client_hello = alice.create_client_hello()
        assert len(client_hello) >= 42  # Version(2) + Timestamp(8) + PubKey(32)
        
        # ServerHello  
        server_hello, bob_secret = bob.process_client_hello(client_hello)
        assert len(server_hello) >= 50
        assert bob_secret is not None
        
        # Client processes ServerHello
        alice_secret = alice.process_server_hello(client_hello, server_hello)
        assert alice_secret is not None
        
        # Verify secrets match
        assert alice_secret == bob_secret
        
        # ClientFinished
        client_finished = alice.create_client_finished(server_hello, alice_secret)
        assert len(client_finished) > 0
        bob.process_client_finished(server_hello, client_finished)
        
        # Verify identities are set
        assert alice.peer_identity_key is not None
        assert bob.peer_identity_key is not None

class TestDoubleRatchet:
    def test_bidirectional_messaging(self):
        """Test bidirectional encrypted messaging"""
        # Setup shared secret
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        # Alice sends first message
        msg1 = b"Hello from Alice"
        encrypted1 = alice.encrypt(msg1)
        decrypted1 = bob.decrypt(encrypted1)
        assert decrypted1 == msg1
        # Bob responds
        msg2 = b"Hello from Bob"
        encrypted2 = bob.encrypt(msg2)
        decrypted2 = alice.decrypt(encrypted2)
        assert decrypted2 == msg2
        # Multiple messages
        for i in range(5):
            msg = f"Message {i}".encode()
            enc = alice.encrypt(msg)
            dec = bob.decrypt(enc)
            assert dec == msg
    
    def test_anti_replay(self):
        """Test anti-replay protection"""
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        # Send and decrypt message
        msg = b"Test message"
        encrypted = alice.encrypt(msg)
        bob.decrypt(encrypted)
        # Try to replay - should fail
        with pytest.raises(ValueError, match="Replay detected"):
            bob.decrypt(encrypted)

class TestEncryption:
    def test_multilayer_encryption(self):
        """Test hybrid encryption"""
        key = os.urandom(32)
        encryptor = MultiLayerEncryptor(key)
        
        plaintext = b"Secret message"
        associated_data = b"metadata"
        
        ciphertext = encryptor.encrypt(plaintext, associated_data)
        decrypted = encryptor.decrypt(ciphertext, associated_data)
        
        assert decrypted == plaintext
    


class TestAuditLogger:
    def test_hash_chain_integrity(self):
        """Test audit log hash chain"""
        # Use a fixed secret key for testing so verify_chain can reproduce the same hash
        test_secret = b'test_secret_key_32_bytes_long!!'
        logger = AuditLogger(log_file="test_audit.log", secret_key=test_secret)
        
        # Log some events
        logger.log_event("TEST_EVENT_1", {"data": "test1"})
        logger.log_event("TEST_EVENT_2", {"data": "test2"})
        logger.log_event("TEST_EVENT_3", {"data": "test3"})
        
        # Close logger handlers before verification
        for handler in logger.logger.handlers:
            handler.close()
            logger.logger.removeHandler(handler)
        
        # Verify chain - create new instance with same secret
        verifier = AuditLogger(log_file="test_audit.log", secret_key=test_secret)
        result = verifier.verify_chain()
        
        # Close verifier handlers
        for handler in verifier.logger.handlers:
            handler.close()
            verifier.logger.removeHandler(handler)
        
        assert result == True
        
        # Cleanup
        if os.path.exists("test_audit.log"):
            try:
                os.remove("test_audit.log")
            except PermissionError:
                pass  # File may still be locked, skip cleanup

class TestSecureWipe:
    def test_memory_wiping(self):
        """Test secure memory wiping"""
        data = bytearray(b"sensitive data")
        original_len = len(data)
        
        secure_wipe(data)
        
        # Data should be zeroed
        assert len(data) == original_len
        assert all(b == 0 for b in data)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
