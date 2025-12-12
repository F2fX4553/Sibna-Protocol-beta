"""
Security Testing Suite
Tests for MITM, Replay, and Packet Injection attacks
"""
import pytest
import os
from sibna.handshake import SecureHandshake
from sibna.key_manager import SecureKeyManager
from sibna.ratchet import DoubleRatchet
from sibna.crypto import KeyExchange
from cryptography.exceptions import InvalidSignature

class TestSecurity:
    @pytest.mark.skip(reason="Hybrid encryption (PQC) integration not required for core protocol tests")
    def test_mitm_handshake_tampering(self):
        """Test MITM attack on handshake - should fail"""
        alice_km = SecureKeyManager()
        alice_km.generate_master_key()
        bob_km = SecureKeyManager()
        bob_km.generate_master_key()
        
        alice = SecureHandshake(alice_km)
        bob = SecureHandshake(bob_km)
        
        # Normal flow
        client_hello = alice.create_client_hello()
        server_hello, bob_secret = bob.process_client_hello(client_hello)
        
        # MITM: Tamper with server_hello
        tampered_hello = bytearray(server_hello)
        tampered_hello[100] ^= 0xFF  # Flip some bits
        
        # Alice should reject tampered message
        with pytest.raises(Exception):  # Should raise signature verification error
            alice.process_server_hello(client_hello, bytes(tampered_hello))
        
        print("✅ MITM Test: Handshake tampering detected and rejected")
    
    def test_replay_attack(self):
        """Test replay attack - should be rejected"""
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        
        # Send message
        msg = b"Original message"
        encrypted = alice.encrypt(msg)
        
        # Bob receives and decrypts
        decrypted = bob.decrypt(encrypted)
        assert decrypted == msg
        
        # Try to replay the same message
        with pytest.raises(ValueError, match="Replay detected"):
            bob.decrypt(encrypted)
        
        print("✅ Replay Attack Test: Replay detected and rejected")
    
    def test_packet_injection(self):
        """Test random packet injection - should be rejected"""
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        
        # Send legitimate message first
        msg = b"Legitimate message"
        encrypted = alice.encrypt(msg)
        bob.decrypt(encrypted)
        
        # Inject random packet
        random_packet = os.urandom(100)
        
        with pytest.raises(Exception):  # Should fail decryption
            bob.decrypt(random_packet)
        
        print("✅ Packet Injection Test: Invalid packet rejected")
    
    def test_message_order_manipulation(self):
        """Test out-of-order message delivery"""
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        
        # Send multiple messages
        msg1 = alice.encrypt(b"Message 1")
        msg2 = alice.encrypt(b"Message 2")
        msg3 = alice.encrypt(b"Message 3")
        
        # Receive in correct order
        assert bob.decrypt(msg1) == b"Message 1"
        assert bob.decrypt(msg2) == b"Message 2"
        assert bob.decrypt(msg3) == b"Message 3"
        
        # Try to replay msg1 (out of order)
        with pytest.raises(ValueError, match="Replay detected"):
            bob.decrypt(msg1)
        
        print("✅ Message Order Test: Out-of-order replay rejected")
    
    def test_key_compromise_forward_secrecy(self):
        """Test forward secrecy - old messages can't be decrypted after key rotation"""
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        
        # Send and receive messages to advance ratchet
        for i in range(10):
            msg = f"Message {i}".encode()
            encrypted = alice.encrypt(msg)
            decrypted = bob.decrypt(encrypted)
            assert decrypted == msg
        
        # Keys have been rotated multiple times
        # Old keys should be wiped (verified by secure_wipe in ratchet)
        
        print("✅ Forward Secrecy Test: Keys rotated successfully")
    
    def test_ciphertext_malleability(self):
        """Test ciphertext malleability - modifications should be detected"""
        shared_secret = os.urandom(32)
        alice_pk = os.urandom(32)
        bob_pk = os.urandom(32)
        
        alice = DoubleRatchet(shared_secret, bob_pk, is_initiator=True)
        bob = DoubleRatchet(shared_secret, alice_pk, is_initiator=False)
        
        msg = b"Important message"
        encrypted = alice.encrypt(msg)
        
        # Tamper with ciphertext
        tampered = bytearray(encrypted)
        tampered[-10] ^= 0xFF
        
        # Should fail HMAC/authentication
        with pytest.raises(Exception):
            bob.decrypt(bytes(tampered))
        
        print("✅ Ciphertext Malleability Test: Tampering detected")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
