import time
import hashlib
import logging
from typing import Dict, Set
from threading import Lock

logger = logging.getLogger(__name__)

class ReplayProtector:
    def __init__(self, window_size: int = 300):
        self.window_size = window_size
        self.seen_messages: Dict[str, Set[str]] = {}
        self.lock = Lock()
        self.cleanup_interval = 60
        
    def _get_time_window(self) -> int:
        """الحصول على النافذة الزمنية الحالية"""
        return int(time.time() // self.window_size)
    
    def _cleanup_old_windows(self):
        """تنظيف النوافذ الزمنية القديمة"""
        current_window = self._get_time_window()
        with self.lock:
            expired_windows = [w for w in self.seen_messages.keys() 
                             if int(w) < current_window - 1]
            for window in expired_windows:
                del self.seen_messages[window]
    
    def is_replay_attack(self, message: bytes, identifier: str) -> bool:
        """التحقق مما إذا كانت الرسالة إعادة تشغيل"""
        try:
            self._cleanup_old_windows()
            
            message_hash = hashlib.sha256(message + identifier.encode()).hexdigest()
            current_window = str(self._get_time_window())
            previous_window = str(self._get_time_window() - 1)
            
            with self.lock:
                if (current_window in self.seen_messages and 
                    message_hash in self.seen_messages[current_window]):
                    logger.warning(f"🚨 Replay attack detected: {identifier}")
                    return True
                
                if (previous_window in self.seen_messages and 
                    message_hash in self.seen_messages[previous_window]):
                    logger.warning(f"🚨 Replay attack detected (previous window): {identifier}")
                    return True
                
                if current_window not in self.seen_messages:
                    self.seen_messages[current_window] = set()
                self.seen_messages[current_window].add(message_hash)
                
                return False
                
        except Exception as e:
            logger.error(f"Error in replay protection: {e}")
            return True
    
    def record_message(self, message: bytes, identifier: str):
        """تسجيل رسالة جديدة"""
        try:
            message_hash = hashlib.sha256(message + identifier.encode()).hexdigest()
            current_window = str(self._get_time_window())
            
            with self.lock:
                if current_window not in self.seen_messages:
                    self.seen_messages[current_window] = set()
                self.seen_messages[current_window].add(message_hash)
                
        except Exception as e:
            logger.error(f"Error recording message: {e}")