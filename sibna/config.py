import os
import secrets
from typing import Optional, List
from pydantic import Field, ConfigDict
from pydantic_settings import BaseSettings

class ServerConfig(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
    )
    
    # Network
    host: str = Field(default="0.0.0.0", alias="OBSIDIAN_HOST")
    port: int = Field(default=4433, alias="OBSIDIAN_PORT")
    max_connections: int = Field(default=1000, alias="OBSIDIAN_MAX_CONNECTIONS")
    log_level: str = Field(default="INFO", alias="OBSIDIAN_LOG_LEVEL")
    
    # Security
    auth_token: str = Field(default_factory=lambda: secrets.token_urlsafe(32), alias="OBSIDIAN_AUTH_TOKEN")
    tls_cert_path: Optional[str] = Field(default=None, alias="OBSIDIAN_TLS_CERT")
    tls_key_path: Optional[str] = Field(default=None, alias="OBSIDIAN_TLS_KEY")
    
    # Obfuscation
    fake_hosts: List[str] = Field(
        default=[
            "cdn.google.com",
            "ajax.microsoft.com", 
            "assets.aws.com",
            "static.cloudflare.com"
        ],
        alias="OBSIDIAN_FAKE_HOSTS"
    )
    fake_paths: List[str] = Field(
        default=[
            "/api/v1/analytics",
            "/static/css/main.css",
            "/uploads/images/avatar.png",
            "/feed/rss.xml"
        ],
        alias="OBSIDIAN_FAKE_PATHS"
    )
    
    # Advanced Security
    jitter: bool = Field(default=True, alias="OBSIDIAN_JITTER")
    max_packet_size: int = Field(default=10 * 1024 * 1024, alias="OBSIDIAN_MAX_PACKET_SIZE")
    socket_timeout: float = Field(default=15.0, alias="OBSIDIAN_SOCKET_TIMEOUT")
    allow_insecure_fallback: bool = Field(default=False, alias="OBSIDIAN_ALLOW_INSECURE")
    
    # Rate Limiting & DDoS Protection
    rate_limit_enabled: bool = Field(default=True, alias="OBSIDIAN_RATE_LIMIT_ENABLED")
    rate_limit_requests: int = Field(default=100, alias="OBSIDIAN_RATE_LIMIT_REQUESTS")
    rate_limit_connections: int = Field(default=10, alias="OBSIDIAN_RATE_LIMIT_CONNECTIONS")
    rate_limit_blacklist_threshold: int = Field(default=1000, alias="OBSIDIAN_RATE_LIMIT_BLACKLIST")
    
    # Audit Logging
    audit_log_enabled: bool = Field(default=True, alias="OBSIDIAN_AUDIT_LOG_ENABLED")
    audit_log_path: str = Field(default="./logs/audit.log", alias="OBSIDIAN_AUDIT_LOG_PATH")
    audit_log_level: str = Field(default="INFO", alias="OBSIDIAN_AUDIT_LOG_LEVEL")
    
    # Monitoring
    prometheus_enabled: bool = Field(default=False, alias="OBSIDIAN_PROMETHEUS_ENABLED")
    prometheus_port: int = Field(default=9090, alias="OBSIDIAN_PROMETHEUS_PORT")

# Global Config Instance
config = ServerConfig()

# Backwards Compatibility / Helper Functions
def get_auth_token() -> str:
    return config.auth_token

def get_fake_host() -> str:
    import random
    return random.choice(config.fake_hosts)

def get_fake_path() -> str:
    import random
    return random.choice(config.fake_paths)

# Constants for other modules
PROTOCOL_VER = 0x12
MAX_PACKET_SIZE = config.max_packet_size
SOCKET_TIMEOUT = config.socket_timeout
JITTER_ENABLED = config.jitter
ALLOW_INSECURE_FALLBACK = config.allow_insecure_fallback