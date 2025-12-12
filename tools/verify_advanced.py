import sys
import os
import logging

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sibna.kyber import MockKyber768
from sibna.ratchet import DoubleRatchet
from sibna.onion import OnionPacket
from sibna.pki import IdentityManager
from sibna.transports.webrtc import WebRtcTransport
from sibna.crypto import KeyExchange

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Verification")

def test_kyber():
    logger.info("Testing Kyber-768 (Mock)...")
    kyber = MockKyber768()
    pk, sk = kyber.keygen()
    
    ct, ss_sender = kyber.encaps(pk)
    ss_receiver = kyber.decaps(ct, sk)
    
    assert ss_sender == ss_receiver
    logger.info("✅ Kyber Shared Secret Match")

def test_ratchet():
    logger.info("Testing Double Ratchet...")
    # Setup shared secret and peer keys
    shared_secret = os.urandom(32)
    
    # Bob's key pair
    bob_keys = KeyExchange()
    peer_pk = bob_keys.get_public_bytes()
    
    alice = DoubleRatchet(shared_secret, peer_pk, is_initiator=True)
    bob = DoubleRatchet(shared_secret, alice.key_exchange.get_public_bytes(), is_initiator=False, key_pair=bob_keys)
    
    # Alice sends to Bob
    msg1 = b"Hello Bob"
    enc1 = alice.encrypt(msg1)
    
    # Bob decrypts
    dec1 = bob.decrypt(enc1)
    assert dec1 == msg1
    logger.info(f"✅ Message 1 Decrypted: {dec1}")
    
    # Reply
    msg2 = b"Hello Alice"
    enc2 = bob.encrypt(msg2)
    dec2 = alice.decrypt(enc2)
    assert dec2 == msg2
    logger.info(f"✅ Message 2 Decrypted: {dec2}")

def test_onion():
    logger.info("Testing Onion Packet...")
    payload = b"Secret Payload"
    packet = OnionPacket(("127.0.0.1", 8080), payload)
    packed = packet.pack()
    
    ip, port, data = OnionPacket.unpack(packed)
    assert ip == "127.0.0.1"
    assert port == 8080
    assert data == payload
    logger.info("✅ Onion Packet Pack/Unpack Successful")

def test_pki():
    logger.info("Testing PKI...")
    pki = IdentityManager()
    priv, cert = pki.create_identity("user_alice")
    
    assert pki.is_valid(cert)
    logger.info(f"✅ Certificate Valid for {cert.user_id}")
    
    # Verify signature
    assert cert.verify(priv.public_key())
    logger.info("✅ Certificate Signature Verified")

if __name__ == "__main__":
    try:
        test_kyber()
        test_ratchet()
        test_onion()
        test_pki()
        print("\n✨ All Advanced Features Verified Successfully!")
    except Exception as e:
        logger.error(f"❌ Verification Failed: {e}")
        sys.exit(1)
