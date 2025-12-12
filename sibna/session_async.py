"""
Async Session Management with ThreadPoolExecutor
Enables high-performance concurrent session handling
"""
import asyncio
import logging
from typing import Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from sibna.ratchet import DoubleRatchet
from sibna.crypto import secure_wipe

logger = logging.getLogger(__name__)

class AsyncObsidianSession:
    """
    Async session manager for high-performance concurrent operations
    """
    
    # Shared thread pool for all sessions
    _executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="obsidian")
    
    def __init__(self, session_id: str, ratchet: DoubleRatchet):
        self.session_id = session_id
        self.ratchet = ratchet
        self.active = True
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }
    
    async def encrypt_async(self, plaintext: bytes) -> bytes:
        """Async encryption using thread pool"""
        loop = asyncio.get_event_loop()
        ciphertext = await loop.run_in_executor(
            self._executor,
            self.ratchet.encrypt,
            plaintext
        )
        self.stats['messages_sent'] += 1
        self.stats['bytes_sent'] += len(ciphertext)
        return ciphertext
    
    async def decrypt_async(self, ciphertext: bytes) -> bytes:
        """Async decryption using thread pool"""
        loop = asyncio.get_event_loop()
        plaintext = await loop.run_in_executor(
            self._executor,
            self.ratchet.decrypt,
            ciphertext
        )
        self.stats['messages_received'] += 1
        self.stats['bytes_received'] += len(ciphertext)
        return plaintext
    
    async def send_message(self, message: bytes, transport_send_func) -> bool:
        """
        Encrypt and send message asynchronously
        
        Args:
            message: Plaintext message
            transport_send_func: Async function to send encrypted data
        """
        try:
            encrypted = await self.encrypt_async(message)
            await transport_send_func(encrypted)
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False
    
    async def receive_message(self, transport_recv_func) -> Optional[bytes]:
        """
        Receive and decrypt message asynchronously
        
        Args:
            transport_recv_func: Async function to receive encrypted data
        """
        try:
            encrypted = await transport_recv_func()
            if not encrypted:
                return None
            plaintext = await self.decrypt_async(encrypted)
            return plaintext
        except Exception as e:
            logger.error(f"Failed to receive message: {e}")
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        return self.stats.copy()
    
    async def close(self):
        """Close session and cleanup"""
        self.active = False
        # Secure wipe would happen in ratchet cleanup
        logger.info(f"Session {self.session_id} closed")

class AsyncSessionManager:
    """
    Manages multiple async sessions concurrently
    """
    
    def __init__(self):
        self.sessions: Dict[str, AsyncObsidianSession] = {}
    
    def create_session(self, session_id: str, ratchet: DoubleRatchet) -> AsyncObsidianSession:
        """Create a new async session"""
        session = AsyncObsidianSession(session_id, ratchet)
        self.sessions[session_id] = session
        logger.info(f"Created session {session_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[AsyncObsidianSession]:
        """Get existing session"""
        return self.sessions.get(session_id)
    
    async def close_session(self, session_id: str):
        """Close and remove session"""
        session = self.sessions.pop(session_id, None)
        if session:
            await session.close()
    
    async def close_all(self):
        """Close all sessions"""
        tasks = [self.close_session(sid) for sid in list(self.sessions.keys())]
        await asyncio.gather(*tasks)
    
    async def broadcast(self, message: bytes, transport_send_funcs: Dict[str, Any]):
        """
        Broadcast message to multiple sessions concurrently
        
        Args:
            message: Message to broadcast
            transport_send_funcs: Dict of session_id -> send function
        """
        tasks = []
        for session_id, send_func in transport_send_funcs.items():
            session = self.get_session(session_id)
            if session and session.active:
                tasks.append(session.send_message(message, send_func))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        successful = sum(1 for r in results if r is True)
        logger.info(f"Broadcast to {successful}/{len(tasks)} sessions")
        return successful
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all sessions"""
        return {
            sid: session.get_stats()
            for sid, session in self.sessions.items()
        }

# Example usage
async def example_concurrent_sessions():
    """Example of handling multiple concurrent sessions"""
    import os
    from sibna.ratchet import DoubleRatchet
    
    manager = AsyncSessionManager()
    
    # Create multiple sessions
    sessions = []
    for i in range(10):
        shared_secret = os.urandom(32)
        peer_pk = os.urandom(32)
        ratchet = DoubleRatchet(shared_secret, peer_pk, is_initiator=True)
        session = manager.create_session(f"session_{i}", ratchet)
        sessions.append(session)
    
    # Simulate concurrent message sending
    async def mock_send(data):
        await asyncio.sleep(0.01)  # Simulate network delay
    
    tasks = []
    for session in sessions:
        for j in range(100):
            msg = f"Message {j} from {session.session_id}".encode()
            tasks.append(session.send_message(msg, mock_send))
    
    # Execute all concurrently
    results = await asyncio.gather(*tasks)
    successful = sum(1 for r in results if r)
    print(f"Sent {successful}/{len(tasks)} messages successfully")
    
    # Get stats
    stats = manager.get_all_stats()
    for sid, stat in stats.items():
        print(f"{sid}: {stat}")
    
    # Cleanup
    await manager.close_all()

if __name__ == "__main__":
    asyncio.run(example_concurrent_sessions())
