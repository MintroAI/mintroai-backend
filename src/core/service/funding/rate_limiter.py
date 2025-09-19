"""Rate limiter for funding service."""

import time
from typing import Dict, Optional
from datetime import datetime, timedelta

from src.infra.config.redis import get_redis
from src.core.logger.logger import logger


class FundingRateLimiter:
    """Rate limiter for funding operations."""
    
    # Rate limit configuration
    DAILY_LIMIT = 10  # Max funding requests per day per user
    RATE_LIMIT_WINDOW = 86400  # 24 hours in seconds
    
    def __init__(self):
        """Initialize rate limiter."""
        self.redis = None  # Will be initialized on first use
    
    async def check_rate_limit(self, user_wallet: str) -> Dict:
        """
        Check if user has exceeded rate limit.
        
        Args:
            user_wallet: User's wallet address
            
        Returns:
            Dict with rate limit info
        """
        try:
            # Get Redis connection if not already initialized
            if not self.redis:
                self.redis = await get_redis()
            
            # Create key for user's daily funding count
            key = f"funding:rate_limit:{user_wallet}:{datetime.utcnow().strftime('%Y%m%d')}"
            
            # Get current count
            current_count = await self.redis.get(key)
            current_count = int(current_count) if current_count else 0
            
            # Calculate next reset time (midnight UTC)
            now = datetime.utcnow()
            tomorrow = now + timedelta(days=1)
            next_reset = datetime(tomorrow.year, tomorrow.month, tomorrow.day, 0, 0, 0)
            next_reset_timestamp = int(next_reset.timestamp())
            
            # Check if limit exceeded
            if current_count >= self.DAILY_LIMIT:
                return {
                    "allowed": False,
                    "error": "Rate limit exceeded",
                    "message": "Daily funding limit reached. Try again tomorrow.",
                    "rate_limit_info": {
                        "daily_limit": self.DAILY_LIMIT,
                        "daily_used": current_count,
                        "daily_remaining": 0,
                        "next_reset": next_reset_timestamp
                    }
                }
            
            return {
                "allowed": True,
                "rate_limit_info": {
                    "daily_limit": self.DAILY_LIMIT,
                    "daily_used": current_count,
                    "daily_remaining": self.DAILY_LIMIT - current_count,
                    "next_reset": next_reset_timestamp
                }
            }
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # If Redis fails, allow the request
            return {
                "allowed": True,
                "rate_limit_info": {
                    "daily_limit": self.DAILY_LIMIT,
                    "daily_used": 0,
                    "daily_remaining": self.DAILY_LIMIT,
                    "next_reset": 0
                }
            }
    
    async def increment_count(self, user_wallet: str):
        """
        Increment user's funding count.
        
        Args:
            user_wallet: User's wallet address
        """
        try:
            # Get Redis connection if not already initialized
            if not self.redis:
                self.redis = await get_redis()
            
            # Create key for user's daily funding count
            key = f"funding:rate_limit:{user_wallet}:{datetime.utcnow().strftime('%Y%m%d')}"
            
            # Increment count
            await self.redis.incr(key)
            
            # Set expiration to end of day
            await self.redis.expire(key, self.RATE_LIMIT_WINDOW)
            
            logger.info(f"Incremented funding count for {user_wallet}")
            
        except Exception as e:
            logger.error(f"Failed to increment rate limit count: {e}")
