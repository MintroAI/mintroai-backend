"""
PostgreSQL database connection with SQLAlchemy ORM
"""

from typing import Optional, AsyncGenerator
from functools import lru_cache
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine

from src.infra.config.settings import get_settings
from src.core.logger.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class DatabaseManager:
    """SQLAlchemy async database manager"""
    
    def __init__(self):
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker] = None
    
    def _build_database_url(self) -> str:
        """Build PostgreSQL connection URL"""
        return (
            f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
            f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
        )
    
    async def connect(self) -> AsyncEngine:
        """Initialize database engine and session factory"""
        if self._engine is not None:
            return self._engine
        
        try:
            database_url = self._build_database_url()
            
            # Create async engine (asyncpg handles its own pooling)
            self._engine = create_async_engine(
                database_url,
                echo=settings.DB_LOGGING_ENABLED,
                pool_pre_ping=True,
                pool_size=settings.POSTGRES_MIN_POOL_SIZE,
                max_overflow=settings.POSTGRES_MAX_POOL_SIZE - settings.POSTGRES_MIN_POOL_SIZE,
                pool_recycle=3600
            )
            
            # Create session factory
            self._session_factory = async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autocommit=False,
                autoflush=False
            )
            
            # Test connection
            async with self._engine.begin() as conn:
                from sqlalchemy import text
                result = await conn.execute(text("SELECT version()"))
                version_row = result.fetchone()
                version = version_row[0] if version_row else "unknown"
                
                logger.info(
                    "Connected to PostgreSQL with SQLAlchemy successfully",
                    extra={
                        "host": settings.POSTGRES_HOST,
                        "port": settings.POSTGRES_PORT,
                        "database": settings.POSTGRES_DB,
                        "pool_size": f"{settings.POSTGRES_MIN_POOL_SIZE}-{settings.POSTGRES_MAX_POOL_SIZE}",
                        "version": version[:50] if version else "unknown"
                    }
                )
            
            return self._engine
            
        except Exception as e:
            logger.error(
                "Failed to connect to PostgreSQL",
                extra={
                    "host": settings.POSTGRES_HOST,
                    "port": settings.POSTGRES_PORT,
                    "database": settings.POSTGRES_DB,
                    "error": str(e)
                }
            )
            raise
    
    async def close(self):
        """Close database engine"""
        if self._engine is not None:
            try:
                await self._engine.dispose()
                logger.info("PostgreSQL engine closed")
                self._engine = None
                self._session_factory = None
            except Exception as e:
                logger.error(f"Error closing PostgreSQL engine: {e}")
    
    def get_engine(self) -> Optional[AsyncEngine]:
        """Get the current engine"""
        return self._engine
    
    def get_session_factory(self) -> Optional[async_sessionmaker]:
        """Get the session factory"""
        return self._session_factory


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


@lru_cache()
def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance (cached)"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting async database session
    Use with FastAPI Depends()
    """
    db_manager = get_database_manager()
    
    if db_manager.get_session_factory() is None:
        await db_manager.connect()
    
    session_factory = db_manager.get_session_factory()
    if session_factory is None:
        raise RuntimeError("Database session factory not initialized")
    
    async with session_factory() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()
