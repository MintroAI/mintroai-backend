import redis.asyncio as redis
from src.infra.config.settings import settings
from src.core.logger.logger import logger

async def get_redis() -> redis.Redis:
    """Get Redis connection"""
    try:
        redis_client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=settings.REDIS_MAX_CONNECTIONS
        )
        # Test connection
        await redis_client.ping()
        logger.info("Connected to Redis successfully")
        return redis_client
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise