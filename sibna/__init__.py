"""
Sibna Protocol - Sovereign Communication SDK
"""
import os
import logging

from .errors import SibnaError
from .config import config, get_auth_token, PROTOCOL_VER, JITTER_ENABLED, get_fake_host, get_fake_path
from .handshake import SecureHandshake
from .session import SibnaSession
from .transport import StealthTransport
from .crypto import get_crypto_status
from .packet import pack, unpack

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# Async modules
HAS_ASYNC = False
AsyncSibnaServer = None
AsyncSibnaClient = None

# Security modules
try:
    from .key_manager import SecureKeyManager, default_key_manager
    from .replay_protection import ReplayProtector
    from .audit_logger import AuditLogger
    HAS_SECURITY_MODULES = True
except ImportError:
    HAS_SECURITY_MODULES = False
    SecureKeyManager = None
    default_key_manager = None
    ReplayProtector = None
    AuditLogger = None

__version__ = "3.0.0"

__all__ = [
    'SibnaError',
    'config',
    'get_auth_token',
    'PROTOCOL_VER', 
    'JITTER_ENABLED',
    'get_fake_host',
    'get_fake_path',
    'SecureHandshake',
    'SibnaSession',
    'StealthTransport',
    'get_crypto_status',
    'pack',
    'unpack',
]

if HAS_SECURITY_MODULES:
    __all__.extend(['SecureKeyManager', 'default_key_manager', 'ReplayProtector', 'AuditLogger'])
