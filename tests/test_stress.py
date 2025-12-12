"""
Stress Testing Suite for Obsidian Sovereign
Tests protocol stability under high load
"""
import pytest
import asyncio
import os
import time
from sibna.ratchet import DoubleRatchet
from sibna.session_async import AsyncSessionManager
from sibna.crypto import KeyExchange

class TestStress:
    @pytest.mark.asyncio
    async def test_concurrent_sessions(self):
        """Test 50 concurrent sessions with 100 messages each"""
        manager = AsyncSessionManager()
        num_sessions = 50
        messages_per_session = 100
        
        # Create sessions
        sessions = []
        for i in range(num_sessions):
            shared_secret = os.urandom(32)
            peer_pk = os.urandom(32)
            ratchet = DoubleRatchet(shared_secret, peer_pk, is_initiator=True)
            session = manager.create_session(f"stress_session_{i}", ratchet)
            sessions.append(session)
        
        # Mock transport
        async def mock_send(data):
            await asyncio.sleep(0.001)
        
        # Send messages concurrently
        start_time = time.time()
        tasks = []
        for session in sessions:
            for j in range(messages_per_session):
                msg = f"Stress test message {j}".encode()
                tasks.append(session.send_message(msg, mock_send))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        # Verify
        successful = sum(1 for r in results if r is True)
        total_messages = num_sessions * messages_per_session
        
        print(f"\n✅ Stress Test Results:")
        print(f"   Sessions: {num_sessions}")
        print(f"   Messages per session: {messages_per_session}")
        print(f"   Total messages: {total_messages}")
        print(f"   Successful: {successful}")
        print(f"   Failed: {total_messages - successful}")
        print(f"   Time: {elapsed:.2f}s")
        print(f"   Throughput: {successful/elapsed:.0f} msg/s")
        
        assert successful >= total_messages * 0.95  # 95% success rate
        
        # Cleanup
        await manager.close_all()
    
    @pytest.mark.asyncio
    async def test_high_volume_single_session(self):
        """Test single session with 5000 messages"""
        manager = AsyncSessionManager()
        
        shared_secret = os.urandom(32)
        peer_pk = os.urandom(32)
        ratchet = DoubleRatchet(shared_secret, peer_pk, is_initiator=True)
        session = manager.create_session("high_volume", ratchet)
        
        async def mock_send(data):
            pass  # No delay for max throughput
        
        num_messages = 5000
        start_time = time.time()
        
        tasks = []
        for i in range(num_messages):
            msg = f"Message {i}".encode()
            tasks.append(session.send_message(msg, mock_send))
        
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        successful = sum(1 for r in results if r)
        
        print(f"\n✅ High Volume Test Results:")
        print(f"   Messages: {num_messages}")
        print(f"   Successful: {successful}")
        print(f"   Time: {elapsed:.2f}s")
        print(f"   Throughput: {successful/elapsed:.0f} msg/s")
        
        assert successful == num_messages
        
        await manager.close_all()
    
    @pytest.mark.asyncio
    async def test_memory_stability(self):
        """Test memory stability with continuous encryption/decryption"""
        import gc
        
        shared_secret = os.urandom(32)
        alice_kex = KeyExchange()
        bob_kex = KeyExchange()
        
        alice = DoubleRatchet(shared_secret, bob_kex.get_public_bytes(), is_initiator=True, key_pair=alice_kex)
        bob = DoubleRatchet(shared_secret, alice_kex.get_public_bytes(), is_initiator=False, key_pair=bob_kex)
        
        # Run 1000 encryption/decryption cycles
        for i in range(1000):
            msg = f"Memory test {i}".encode()
            encrypted = alice.encrypt(msg)
            decrypted = bob.decrypt(encrypted)
            assert decrypted == msg
            
            # Force garbage collection every 100 iterations
            if i % 100 == 0:
                gc.collect()
        
        print("\n✅ Memory Stability Test: 1000 cycles completed")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
