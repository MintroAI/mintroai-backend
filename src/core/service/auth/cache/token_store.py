import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from redis.asyncio import Redis

from src.core.logger.logger import get_logger
from src.core.service.auth.models.token import TokenBlacklist
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class TokenStore:
    """Redis-based store for managing blacklisted tokens"""

    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.key_prefix = "blacklist:token:"
        self.margin_minutes = settings.TOKEN_BLACKLIST_EXPIRE_MARGIN_MINUTES

    def _serialize_datetime(self, dt: datetime) -> str:
        """Convert datetime to ISO format string"""
        return dt.isoformat()

    def _deserialize_datetime(self, dt_str: str) -> datetime:
        """Convert ISO format string to datetime"""
        return datetime.fromisoformat(dt_str)

    def _serialize_blacklist_entry(self, entry: TokenBlacklist) -> Dict[str, Any]:
        """Convert TokenBlacklist to JSON-serializable dict"""
        data = entry.model_dump()
        data["exp"] = self._serialize_datetime(data["exp"])
        data["blacklisted_at"] = self._serialize_datetime(data["blacklisted_at"])
        return data

    def _deserialize_blacklist_entry(self, data: Dict[str, Any]) -> TokenBlacklist:
        """Convert JSON dict to TokenBlacklist"""
        data["exp"] = self._deserialize_datetime(data["exp"])
        data["blacklisted_at"] = self._deserialize_datetime(data["blacklisted_at"])
        return TokenBlacklist(**data)

    async def add_to_blacklist(
        self,
        jti: str,
        exp: datetime,
        reason: Optional[str] = None
    ) -> None:
        """
        Add a token to the blacklist
        The token will be automatically removed after its expiration (plus margin)
        """
        try:
            blacklist_entry = TokenBlacklist(
                jti=jti,
                exp=exp,
                reason=reason
            )

            # Calculate TTL: time until expiration + margin
            now = datetime.now(timezone.utc)
            ttl = exp - now + timedelta(minutes=self.margin_minutes)
            ttl_seconds = int(ttl.total_seconds())

            # Don't blacklist if token is already expired
            if ttl_seconds <= 0:
                logger.info(
                    "Skipping blacklist for expired token",
                    extra={"jti": jti}
                )
                return

            key = f"{self.key_prefix}{jti}"
            await self.redis.setex(
                key,
                ttl_seconds,
                json.dumps(self._serialize_blacklist_entry(blacklist_entry))
            )

            logger.info(
                "Token blacklisted",
                extra={
                    "jti": jti,
                    "expires_in": ttl_seconds,
                    "reason": reason
                }
            )

        except Exception as e:
            logger.error(
                "Failed to blacklist token",
                extra={
                    "jti": jti,
                    "error": str(e)
                }
            )
            raise

    async def is_blacklisted(self, jti: str) -> bool:
        """Check if a token is blacklisted"""
        try:
            key = f"{self.key_prefix}{jti}"
            exists = await self.redis.exists(key)
            
            if exists:
                logger.info(
                    "Blacklisted token access attempt",
                    extra={"jti": jti}
                )
            
            return bool(exists)

        except Exception as e:
            logger.error(
                "Failed to check token blacklist",
                extra={
                    "jti": jti,
                    "error": str(e),
                    "error_type": type(e).__name__
                }
            )
            # If we can't check the blacklist, assume token is valid (fail-open for availability)
            # In production, you might want to fail-closed for security
            logger.warning(f"Redis connection failed ({type(e).__name__}: {str(e)}), allowing token access (fail-open mode)")
            return False