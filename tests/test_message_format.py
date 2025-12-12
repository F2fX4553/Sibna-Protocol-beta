"""
Unit tests for message format compliance with whitepaper
"""

import pytest
from sibna.ratchet import DoubleRatchet, MSG_TYPE_DATA, MSG_TYPE_KEEPALIVE, MSG_TYPE_REKEY
from sibna.crypto import KeyExchange


class TestMessageFormatCompliance:
    """Test message format matches whitepaper Section 6.3"""
    
    def test_message_type_constants(self):
        """Test message type constants match whitepaper"""
        assert MSG_TYPE_DATA == 0x10
        assert MSG_TYPE_KEEPALIVE == 0x11
        assert MSG_TYPE_REKEY == 0x12
    
    def test_encrypt_header_format(self):
        """Test encrypted message header format (45 bytes)"""
        # Setup ratchet
        shared_secret = b'0' * 32
        peer_kex = KeyExchange()
        peer_pk = peer_kex.get_public_bytes()
        
        ratchet = DoubleRatchet(shared_secret, peer_pk, is_initiator=True)
        
        # Encrypt message
        plaintext = b"Test message"
        ciphertext = ratchet.encrypt(plaintext)
        
        # Verify header format (per whitepaper Section 6.3.1)
        # Byte 0: Type (0x10)
        assert ciphertext[0] == MSG_TYPE_DATA
        
        # Bytes 1-32: DH Public Key
        dh_pk = ciphertext[1:33]
        assert len(dh_pk) == 32
        
        # Bytes 33-36: Previous N (PN)
        pn = int.from_bytes(ciphertext[33:37], 'big')
        assert pn == 0  # First message
        
        # Bytes 37-40: Message Number (Ns)
        n = int.from_bytes(ciphertext[37:41], 'big')
        assert n == 0  # First message
        
        # Bytes 41-44: Payload Length
        payload_len = int.from_bytes(ciphertext[41:45], 'big')
        assert payload_len == len(plaintext)
        
        # Total header: 45 bytes
        header = ciphertext[:45]
        assert len(header) == 45
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt/decrypt with new format"""
        # Setup two ratchets
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
        
        # Alice encrypts
        plaintext = b"Hello from Alice!"
        ciphertext = alice.encrypt(plaintext)
        
        # Verify format
        assert ciphertext[0] == MSG_TYPE_DATA
        assert len(ciphertext) >= 61  # 45 header + 16 minimum tag
        
        # Bob decrypts
        decrypted = bob.decrypt(ciphertext)
        assert decrypted == plaintext
    
    def test_multiple_messages(self):
        """Test multiple messages with incrementing counters"""
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
        
        # Send multiple messages
        for i in range(5):
            plaintext = f"Message {i}".encode()
            ciphertext = alice.encrypt(plaintext)
            
            # Verify message number increments
            n = int.from_bytes(ciphertext[37:41], 'big')
            assert n == i
            
            # Decrypt
            decrypted = bob.decrypt(ciphertext)
            assert decrypted == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
