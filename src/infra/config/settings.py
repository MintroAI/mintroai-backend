from typing import List, Optional
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # App Settings
    APP_NAME: str = "MintroAI"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    
    # Security Settings
    JWT_SECRET_KEY: str = "your-secret-key"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    TOKEN_BLACKLIST_EXPIRE_MARGIN_MINUTES: int = 5  # Extra time to keep blacklisted tokens
    
    # Rate Limiting
    RATE_LIMIT_MAX_REQUESTS: int = 100  # requests per minute
    SUSPICIOUS_IP_THRESHOLD: int = 5  # failed attempts before blocking
    IP_BLOCK_DURATION: int = 15  # minutes
    
    # Endpoint-specific rate limits (requests per minute)
    RATE_LIMIT_AUTH_CHALLENGE: int = 5  # Challenge creation
    RATE_LIMIT_AUTH_VERIFY: int = 3     # Signature verification  
    RATE_LIMIT_AUTH_REFRESH: int = 10   # Token refresh
    RATE_LIMIT_AUTH_LOGOUT: int = 20    # Logout requests
    RATE_LIMIT_DEFAULT: int = 30        # Default for other endpoints
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",  # Frontend development
        "https://app.mintroai.com",  # Production frontend
        "file://*",  # Local HTML files for testing
        "null"  # For file:// protocol
    ]

    # Redis Settings
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_MAX_CONNECTIONS: int = 10
    
    # Challenge Settings
    CHALLENGE_EXPIRY_SECONDS: int = 300  # 5 minutes

    # Session Settings
    SESSION_INACTIVITY_MINUTES: int = 60  # 1 hour

    # Security Settings
    JWT_SECRET_LENGTH: int = 32  # 256 bits
    MAX_FAILED_AUTH_ATTEMPTS: int = 5
    AUTH_LOCKOUT_MINUTES: int = 30
    AUDIT_LOG_RETENTION_DAYS: int = 90

    # Protocol Settings
    SUPPORTED_PROTOCOLS: List[str] = ["evm", "near"]
    DEFAULT_PROTOCOL: str = "evm"
    
    # NEAR Protocol Settings
    NEAR_NETWORK_ID: str = "mainnet"  # testnet or mainnet
    NEAR_RPC_URLS: List[str] = [
        "https://rpc.mainnet.near.org",
        "https://rpc.fastnear.com"
    ]
    NEAR_MAX_RETRIES: int = 3
    NEAR_TIMEOUT_SECONDS: int = 30
    
    # Chain Signatures Funding Settings
    NEXT_PUBLIC_FUNDER_PRIVATE_KEY: Optional[str] = None  # Private key for funding wallet
    NEAR_ENABLED: bool = True
    
    # n8n Workflow Settings
    N8N_TOKEN_WORKFLOW_URL: str = "https://barisarya.app.n8n.cloud/webhook/b8bce491-1fee-470c-aa7a-20a5e619fa51"
    N8N_VESTING_WORKFLOW_URL: str = "https://mintro.app.n8n.cloud/webhook/9a30de38-7fbc-4de1-bac3-69f5b627304f"
    N8N_GENERAL_WORKFLOW_URL: str = "https://chaingpt-proxy-production.up.railway.app/chat/general"
    
    # Contract Generation Settings
    CONTRACT_GENERATOR_URL: Optional[str] = None  # External contract generation service URL
    CONTRACT_GENERATION_DAILY_LIMIT: int = 50  # Daily limit per user
    EXTERNAL_SERVICE_TOKEN: Optional[str] = None  # Optional auth token for external service
    
    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()