import logging
import json
import time
import hashlib
import hmac
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class AuditLogger:
    def __init__(self, log_file: str = "obsidian_audit.log", secret_key: Optional[bytes] = None):
        self.log_file = log_file
        self.secret_key = secret_key or os.environ.get("OBSIDIAN_AUDIT_KEY", os.urandom(32))
        if isinstance(self.secret_key, str):
            self.secret_key = self.secret_key.encode()
            
        self.last_hash = b'\x00' * 32
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logger = logging.getLogger('obsidian_audit')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.FileHandler(self.log_file)
            formatter = logging.Formatter('%(message)s') # We format the JSON ourselves
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.propagate = False
        
        self.logger = logger
        
        # Recover last hash if file exists
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = json.loads(lines[-1])
                        self.last_hash = bytes.fromhex(last_line.get('hash', '00'*32))
            except Exception:
                pass
    
    def log_event(self, event_type: str, details: Dict[str, Any], 
                  user: Optional[str] = None, severity: str = "INFO"):
        """Log a security event with HMAC chaining"""
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Construct payload for hashing
            payload = {
                'timestamp': timestamp,
                'event_type': event_type,
                'user': user,
                'severity': severity,
                'details': details,
                'prev_hash': self.last_hash.hex()
            }
            
            # Calculate HMAC
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            current_hash = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()
            
            # Add hash to log entry
            log_entry = payload.copy()
            log_entry['hash'] = current_hash
            
            # Update last hash
            self.last_hash = bytes.fromhex(current_hash)
            
            # Log to file
            self.logger.info(json.dumps(log_entry))
            
            # Also log to console if critical
            if severity == "CRITICAL":
                print(f"🚨 CRITICAL SECURITY EVENT: {event_type} - {details}")
                
            return current_hash
            
        except Exception as e:
            print(f"Failed to log audit event: {e}")
            return None
    
    def log_auth_attempt(self, client_id: str, success: bool, reason: str = ""):
        """Log authentication attempt"""
        details = {
            'client_id': client_id,
            'success': success,
            'reason': reason,
            'ip_address': getattr(self, 'client_ip', 'unknown')
        }
        
        severity = "WARNING" if not success else "INFO"
        return self.log_event(
            "AUTH_ATTEMPT", 
            details, 
            client_id, 
            severity
        )
    
    def log_key_rotation(self, key_manager_stats: Dict):
        """Log key rotation event"""
        return self.log_event(
            "KEY_ROTATION",
            key_manager_stats,
            severity="INFO"
        )
    
    def log_security_incident(self, incident_type: str, details: Dict, user: str = "system"):
        """Log security incident"""
        return self.log_event(
            f"SECURITY_INCIDENT_{incident_type}",
            details,
            user,
            severity="CRITICAL"
        )

    def verify_chain(self) -> bool:
        """Verify the integrity of the audit log chain"""
        try:
            if not os.path.exists(self.log_file):
                return True
                
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            
            prev_hash = '00' * 32  # Initialize with zeros as hex string
            
            for i, line in enumerate(lines):
                entry = json.loads(line)
                stored_hash = entry.get('hash')
                
                if stored_hash is None:
                    print(f"❌ Missing hash at line {i+1}")
                    return False
                
                # Check link to previous entry
                if entry.get('prev_hash') != prev_hash:
                    print(f"❌ Chain broken at line {i+1}: prev_hash mismatch")
                    print(f"   Expected: {prev_hash}")
                    print(f"   Got:      {entry.get('prev_hash')}")
                    return False
                
                # Re-calculate HMAC (excluding the hash field itself)
                entry_for_verification = {k: v for k, v in entry.items() if k != 'hash'}
                payload_bytes = json.dumps(entry_for_verification, sort_keys=True).encode()
                calculated_hash = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()
                
                if calculated_hash != stored_hash:
                    print(f"❌ Hash mismatch at line {i+1}")
                    return False
                
                prev_hash = stored_hash
                
            print("✅ Audit log integrity verified")
            return True
            
        except Exception as e:
            print(f"Verification failed: {e}")
            return False