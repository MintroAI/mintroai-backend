import redis.asyncio as redis
from functools import lru_cache
from src.infra.config.settings import settings
from src.core.logger.logger import logger

@lru_cache()
def get_redis_pool():
    """Get Redis connection pool (cached)"""
    return redis.ConnectionPool.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        max_connections=settings.REDIS_MAX_CONNECTIONS
    )

async def get_redis() -> redis.Redis:
    """Get Redis connection from pool"""
    try:
        pool = get_redis_pool()
        redis_client = redis.Redis(connection_pool=pool)
        # Test connection
        await redis_client.ping()
        logger.info("Connected to Redis successfully")
        return redis_client
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise