import json
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as redis

from src.core.service.auth.models.challenge import Challenge
from src.core.logger.logger import logger


class ChallengeStore:
    """Redis store for managing authentication challenges"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.key_prefix = "auth:challenge:"
    
    def _get_key(self, wallet_address: str) -> str:
        """Get Redis key for wallet address"""
        return f"{self.key_prefix}{wallet_address.lower()}"
    
    def _serialize_challenge(self, challenge: Challenge) -> str:
        """Serialize challenge to JSON string"""
        challenge_dict = challenge.model_dump()
        # Convert datetime objects to ISO format
        challenge_dict["timestamp"] = challenge_dict["timestamp"].isoformat()
        challenge_dict["expires_at"] = challenge_dict["expires_at"].isoformat()
        return json.dumps(challenge_dict)
    
    def _deserialize_challenge(self, data: str) -> Challenge:
        """Deserialize JSON string to Challenge object"""
        challenge_dict = json.loads(data)
        # Convert ISO strings back to datetime objects
        challenge_dict["timestamp"] = datetime.fromisoformat(challenge_dict["timestamp"])
        challenge_dict["expires_at"] = datetime.fromisoformat(challenge_dict["expires_at"])
        return Challenge(**challenge_dict)
    
    async def save_challenge(self, challenge: Challenge) -> None:
        """Save challenge to Redis with TTL"""
        try:
            key = self._get_key(challenge.wallet_address)
            data = self._serialize_challenge(challenge)
            
            # Calculate TTL in seconds
            # Use challenge.expires_at - datetime.now(timezone.utc) for accurate TTL
            ttl = int((challenge.expires_at - datetime.now(timezone.utc)).total_seconds())
            if ttl > 0:
                await self.redis.setex(key, ttl, data)
                logger.debug(
                    "Saved challenge",
                    extra={
                        "wallet_address": challenge.wallet_address,
                        "status": challenge.status,
                        "ttl": ttl
                    }
                )
            else:
                logger.warning(
                    "Attempted to save expired challenge",
                    extra={
                        "wallet_address": challenge.wallet_address,
                        "status": challenge.status
                    }
                )
        
        except Exception as e:
            logger.error(
                "Error saving challenge",
                extra={
                    "wallet_address": challenge.wallet_address,
                    "error": str(e)
                }
            )
            raise
    
    async def get_challenge(self, wallet_address: str) -> Optional[Challenge]:
        """Get challenge from Redis if exists"""
        try:
            key = self._get_key(wallet_address)
            data = await self.redis.get(key)
            
            if not data:
                return None
            
            challenge = self._deserialize_challenge(data)
            if challenge.is_expired():
                await self.delete_challenge(wallet_address)
                logger.warning(
                    "Expired challenge retrieved and deleted",
                    extra={
                        "wallet_address": wallet_address,
                        "status": challenge.status
                    }
                )
                return None
            return challenge
        
        except Exception as e:
            logger.error(
                "Error getting challenge",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise
    
    async def delete_challenge(self, wallet_address: str) -> None:
        """Delete challenge from Redis"""
        try:
            key = self._get_key(wallet_address)
            await self.redis.delete(key)
            logger.debug(
                "Deleted challenge",
                extra={"wallet_address": wallet_address}
            )
        
        except Exception as e:
            logger.error(
                "Error deleting challenge",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise