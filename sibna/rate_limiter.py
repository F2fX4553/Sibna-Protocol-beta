"""
Rate Limiting & DDoS Protection Module
Implements token bucket algorithm for request rate limiting
"""
import time
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting"""
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    
    def __post_init__(self):
        self.tokens = float(self.capacity)
        self.last_refill = time.time()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens, return True if successful"""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def _refill(self):
        """Refill tokens based on time elapsed"""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + (elapsed * self.refill_rate)
        )
        self.last_refill = now


@dataclass
class ClientInfo:
    """Track client connection info"""
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0
    connection_count: int = 0
    violations: int = 0
    blacklisted: bool = False
    bucket: Optional[TokenBucket] = None


class RateLimiter:
    """
    Advanced rate limiter with DDoS protection
    
    Features:
    - Per-IP rate limiting
    - Connection limits
    - Automatic blacklisting
    - Whitelist support
    - Strict Mode (DDoS Protection)
    """
    
    def __init__(
        self,
        requests_per_minute: int = 100,
        max_connections_per_ip: int = 10,
        blacklist_threshold: int = 1000,
        cleanup_interval: int = 300,  # 5 minutes
        enabled: bool = True,
        strict_mode: bool = False
    ):
        self.requests_per_minute = requests_per_minute
        self.max_connections = max_connections_per_ip
        self.blacklist_threshold = blacklist_threshold
        self.cleanup_interval = cleanup_interval
        self.enabled = enabled
        self.strict_mode = strict_mode
        
        self.clients: Dict[str, ClientInfo] = {}
        self.whitelist: set = set()
        self.blacklist: set = set()
        
        self._lock = Lock()
        self._last_cleanup = time.time()
        
        # DDoS Detection
        self.total_requests_window = 0
        self.window_start = time.time()
        self.ddos_threshold = requests_per_minute * 100 # Global threshold
        
        logger.info(
            f"Rate limiter initialized: {requests_per_minute} req/min, "
            f"{max_connections_per_ip} max connections per IP, Strict: {strict_mode}"
        )
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, str]:
        """
        Check if request from IP is allowed
        
        Returns:
            (allowed: bool, reason: str)
        """
        if not self.enabled:
            return True, "rate_limiting_disabled"
        
        # Whitelist always allowed
        if ip in self.whitelist:
            return True, "whitelisted"
        
        # Blacklist always blocked
        if ip in self.blacklist:
            return False, "blacklisted"
        
        with self._lock:
            # Global DDoS Check
            now = time.time()
            if now - self.window_start > 60:
                self.total_requests_window = 0
                self.window_start = now
                # Auto-disable strict mode if traffic normalizes
                if self.strict_mode and self.total_requests_window < self.ddos_threshold / 2:
                    self.strict_mode = False
                    logger.info("📉 Traffic normalized, disabling Strict Mode")
            
            self.total_requests_window += 1
            if self.total_requests_window > self.ddos_threshold:
                if not self.strict_mode:
                    self.strict_mode = True
                    logger.warning("🚨 DDoS detected! Enabling Strict Mode")
            
            # Get or create client info
            client = self._get_or_create_client(ip)
            
            # Check if blacklisted due to violations
            if client.blacklisted:
                self.blacklist.add(ip)
                return False, "auto_blacklisted"
            
            # Check rate limit using token bucket
            if not client.bucket.consume():
                client.violations += 1
                logger.warning(f"Rate limit exceeded for {ip} (violations: {client.violations})")
                
                # Auto-blacklist logic
                threshold = 1 if self.strict_mode else self.blacklist_threshold
                
                if client.violations >= threshold:
                    client.blacklisted = True
                    self.blacklist.add(ip)
                    logger.warning(f"🚫 IP {ip} blacklisted (Strict: {self.strict_mode})")
                    return False, "rate_limit_exceeded_blacklisted"
                
                return False, "rate_limit_exceeded"
            
            # Update stats
            client.request_count += 1
            client.last_seen = time.time()
            
            # Periodic cleanup
            self._maybe_cleanup()
            
            return True, "allowed"
    
    def check_connection_limit(self, ip: str) -> Tuple[bool, str]:
        """Check if new connection from IP is allowed"""
        if not self.enabled:
            return True, "rate_limiting_disabled"
        
        if ip in self.whitelist:
            return True, "whitelisted"
        
        if ip in self.blacklist:
            return False, "blacklisted"
        
        with self._lock:
            client = self._get_or_create_client(ip)
            
            limit = 1 if self.strict_mode else self.max_connections
            
            if client.connection_count >= limit:
                client.violations += 1
                logger.warning(
                    f"Connection limit exceeded for {ip}: "
                    f"{client.connection_count}/{limit}"
                )
                return False, "connection_limit_exceeded"
            
            client.connection_count += 1
            return True, "allowed"
    
    def release_connection(self, ip: str):
        """Release a connection slot for IP"""
        with self._lock:
            if ip in self.clients:
                self.clients[ip].connection_count = max(
                    0, self.clients[ip].connection_count - 1
                )
    
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        self.whitelist.add(ip)
        logger.info(f"Added {ip} to whitelist")
    
    def add_to_blacklist(self, ip: str):
        """Manually add IP to blacklist"""
        self.blacklist.add(ip)
        if ip in self.clients:
            self.clients[ip].blacklisted = True
        logger.warning(f"Manually blacklisted {ip}")
    
    def remove_from_blacklist(self, ip: str):
        """Remove IP from blacklist"""
        self.blacklist.discard(ip)
        if ip in self.clients:
            self.clients[ip].blacklisted = False
            self.clients[ip].violations = 0
        logger.info(f"Removed {ip} from blacklist")
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics"""
        with self._lock:
            return {
                "enabled": self.enabled,
                "strict_mode": self.strict_mode,
                "total_clients": len(self.clients),
                "whitelisted_ips": len(self.whitelist),
                "blacklisted_ips": len(self.blacklist),
                "active_connections": sum(
                    c.connection_count for c in self.clients.values()
                ),
                "total_requests": sum(
                    c.request_count for c in self.clients.values()
                ),
                "total_violations": sum(
                    c.violations for c in self.clients.values()
                )
            }
    
    def _get_or_create_client(self, ip: str) -> ClientInfo:
        """Get existing client or create new one"""
        if ip not in self.clients:
            # Create token bucket: requests_per_minute / 60 = tokens per second
            bucket = TokenBucket(
                capacity=self.requests_per_minute,
                refill_rate=self.requests_per_minute / 60.0
            )
            self.clients[ip] = ClientInfo(ip=ip, bucket=bucket)
        return self.clients[ip]
    
    def _maybe_cleanup(self):
        """Clean up old client entries"""
        now = time.time()
        if now - self._last_cleanup < self.cleanup_interval:
            return
        
        # Remove clients not seen in last hour
        cutoff = now - 3600
        to_remove = [
            ip for ip, client in self.clients.items()
            if client.last_seen < cutoff and client.connection_count == 0
        ]
        
        for ip in to_remove:
            del self.clients[ip]
        
        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} inactive clients")
        
        self._last_cleanup = now


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        # Avoid circular import if config uses this
        try:
            from sibna.config import config
            _rate_limiter = RateLimiter(
                requests_per_minute=getattr(config, 'rate_limit_requests', 100),
                max_connections_per_ip=getattr(config, 'rate_limit_connections', 10),
                blacklist_threshold=getattr(config, 'rate_limit_blacklist_threshold', 1000),
                enabled=getattr(config, 'rate_limit_enabled', True)
            )
        except ImportError:
            _rate_limiter = RateLimiter()
            
    return _rate_limiter


def reset_rate_limiter():
    """Reset global rate limiter (useful for testing)"""
    global _rate_limiter
    _rate_limiter = None
