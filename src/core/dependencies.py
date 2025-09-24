"""
FastAPI dependency injection functions.
Clean, maintainable dependency resolution using FastAPI's native DI system.
"""

from fastapi import Depends
from redis.asyncio import Redis

from src.infra.config.redis import get_redis
from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.cache.challenge_store import ChallengeStore
from src.core.service.auth.cache.token_store import TokenStore
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService


async def get_redis_client() -> Redis:
    """Get Redis client dependency."""
    return await get_redis()


async def get_jwt_service(redis_client: Redis = Depends(get_redis_client)) -> JWTService:
    """Get JWT service with Redis dependency."""
    return JWTService(redis_client)


async def get_challenge_service(redis_client: Redis = Depends(get_redis_client)) -> ChallengeService:
    """Get challenge service with dependencies."""
    challenge_store = ChallengeStore(redis_client)
    multi_signature_service = MultiProtocolSignatureService()
    return ChallengeService(challenge_store, multi_signature_service)


async def get_token_store(redis_client: Redis = Depends(get_redis_client)) -> TokenStore:
    """Get token store with Redis dependency."""
    return TokenStore(redis_client)
