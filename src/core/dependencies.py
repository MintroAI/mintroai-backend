"""
FastAPI dependency injection functions.
Clean, maintainable dependency resolution using FastAPI's native DI system.
"""

from typing import Optional
from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.infra.config.redis import get_redis
from src.infra.database import get_async_session
from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.cache.challenge_store import ChallengeStore
from src.core.service.auth.cache.token_store import TokenStore
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.infra.repository.user_repository import UserRepository
from src.infra.repository.contract_activity_repository import ContractActivityRepository
from src.infra.repository.funding_activity_repository import FundingActivityRepository
from src.api.controller.funding.funding_controller import FundingController
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


async def get_redis_client() -> Redis:
    """Get Redis client dependency."""
    return await get_redis()


async def get_user_repository(session: AsyncSession = Depends(get_async_session)) -> Optional[UserRepository]:
    """Get user repository with SQLAlchemy session dependency."""
    try:
        return UserRepository(session)
    except Exception as e:
        logger.error(f"Failed to create user repository: {e}")
        return None


async def get_contract_activity_repository(session: AsyncSession = Depends(get_async_session)) -> Optional[ContractActivityRepository]:
    """Get contract activity repository with SQLAlchemy session dependency."""
    try:
        return ContractActivityRepository(session)
    except Exception as e:
        logger.error(f"Failed to create contract activity repository: {e}")
        return None


async def get_funding_activity_repository(session: AsyncSession = Depends(get_async_session)) -> Optional[FundingActivityRepository]:
    """Get funding activity repository with SQLAlchemy session dependency."""
    try:
        return FundingActivityRepository(session)
    except Exception as e:
        logger.error(f"Failed to create funding activity repository: {e}")
        return None


async def get_jwt_service(redis_client: Redis = Depends(get_redis_client)) -> JWTService:
    """Get JWT service with Redis dependency."""
    return JWTService(redis_client)


async def get_challenge_service(
    redis_client: Redis = Depends(get_redis_client),
    user_repository: Optional[UserRepository] = Depends(get_user_repository)
) -> ChallengeService:
    """Get challenge service with dependencies."""
    challenge_store = ChallengeStore(redis_client)
    multi_signature_service = MultiProtocolSignatureService()
    return ChallengeService(challenge_store, multi_signature_service, user_repository)


async def get_token_store(redis_client: Redis = Depends(get_redis_client)) -> TokenStore:
    """Get token store with Redis dependency."""
    return TokenStore(redis_client)


async def get_funding_controller(
    redis_client: Redis = Depends(get_redis_client),
    funding_activity_repository: Optional[FundingActivityRepository] = Depends(get_funding_activity_repository)
) -> FundingController:
    """Get funding controller with Redis and activity repository dependencies."""
    return FundingController(redis_client, funding_activity_repository)
