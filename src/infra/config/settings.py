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
    
    # Database Settings
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "mintroai"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    
    # JWT Settings
    JWT_SECRET_KEY: str = "your-secret-key"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
