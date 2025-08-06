from typing import List
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
    
    # Rate Limiting
    RATE_LIMIT_MAX_REQUESTS: int = 5  # Reduced for testing (100 in production)
    SUSPICIOUS_IP_THRESHOLD: int = 3  # Reduced for testing (5 in production)
    IP_BLOCK_DURATION: int = 15  # minutes
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",  # Frontend development
        "https://app.mintroai.com"  # Production frontend
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()