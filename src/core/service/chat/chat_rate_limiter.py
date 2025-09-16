"""
Chat-specific rate limiting service
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple

from src.core.service.chat.models.chat import UserContext, RateLimitInfo
from src.core.logger.logger import get_logger
from src.infra.config.redis import get_redis

logger = get_logger(__name__)


class ChatRateLimitConfig:
    """Configuration for chat rate limiting"""
    
    # Authenticated users: 100 messages per hour
    AUTHENTICATED_LIMIT = 100
    AUTHENTICATED_WINDOW = 3600  # 1 hour in seconds
    
    # Premium users: 500 messages per hour
    PREMIUM_LIMIT = 500
    PREMIUM_WINDOW = 3600  # 1 hour in seconds
    
    # Guest users: 3 messages per 24 hours per IP
    GUEST_LIMIT = 3
    GUEST_WINDOW = 86400  # 24 hours in seconds
    
    # Key prefixes
    KEY_PREFIX = "chat_rate_limit"


class ChatRateLimiter:
    """Rate limiter for chat interactions"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.config = ChatRateLimitConfig()
        self.logger = logger
    
    def _get_rate_limit_key(self, user_context: UserContext, client_ip: str) -> str:
        """Generate rate limit key based on user context"""
        if user_context.user_type == "premium" and user_context.wallet_address:
            return f"{self.config.KEY_PREFIX}:premium:{user_context.wallet_address}"
        elif user_context.is_authenticated and user_context.wallet_address:
            return f"{self.config.KEY_PREFIX}:user:{user_context.wallet_address}"
        else:
            return f"{self.config.KEY_PREFIX}:guest:{client_ip}"
    
    def _get_rate_limit_config(self, user_context: UserContext) -> Tuple[int, int]:
        """Get rate limit configuration based on user type"""
        if user_context.user_type == "premium":
            return self.config.PREMIUM_LIMIT, self.config.PREMIUM_WINDOW
        elif user_context.is_authenticated:
            return self.config.AUTHENTICATED_LIMIT, self.config.AUTHENTICATED_WINDOW
        else:
            return self.config.GUEST_LIMIT, self.config.GUEST_WINDOW
    
    async def check_rate_limit(
        self, 
        user_context: UserContext, 
        client_ip: str
    ) -> Tuple[bool, Optional[RateLimitInfo]]:
        """
        Check if user has exceeded rate limit
        
        Args:
            user_context: User context with authentication info
            client_ip: Client IP address
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        # If Redis is not available, allow all requests
        if not self.redis:
            self.logger.warning("Redis not available - rate limiting disabled")
            return True, None
            
        try:
            key = self._get_rate_limit_key(user_context, client_ip)
            limit, window = self._get_rate_limit_config(user_context)
            
            # Get current count
            current_count = await self.redis.get(key)
            
            if current_count is None:
                # First request in window
                await self.redis.setex(key, window, 1)
                current_count = 1
                ttl = window
            else:
                current_count = int(current_count)
                ttl = await self.redis.ttl(key)
                
                if current_count >= limit:
                    # Rate limit exceeded
                    reset_time = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat() + "Z"
                    
                    self.logger.warning(
                        f"Rate limit exceeded",
                        extra={
                            "user_type": user_context.user_type,
                            "wallet_address": user_context.wallet_address,
                            "client_ip": client_ip,
                            "current_count": current_count,
                            "limit": limit
                        }
                    )
                    
                    rate_limit_info = RateLimitInfo(
                        remaining=0,
                        reset_time=reset_time,
                        limit=limit
                    )
                    return False, rate_limit_info
                
                # Increment counter
                await self.redis.incr(key)
                current_count += 1
            
            # Calculate remaining requests
            remaining = max(0, limit - current_count)
            reset_time = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat() + "Z"
            
            rate_limit_info = RateLimitInfo(
                remaining=remaining,
                reset_time=reset_time,
                limit=limit
            )
            
            self.logger.debug(
                f"Rate limit check passed",
                extra={
                    "user_type": user_context.user_type,
                    "wallet_address": user_context.wallet_address,
                    "remaining": remaining,
                    "limit": limit
                }
            )
            
            return True, rate_limit_info
            
        except Exception as e:
            self.logger.error(
                f"Error checking rate limit: {str(e)}",
                extra={
                    "user_type": user_context.user_type,
                    "client_ip": client_ip
                }
            )
            # On error, allow request but don't provide rate limit info
            return True, None
    
    async def reset_rate_limit(self, wallet_address: str = None, client_ip: str = None):
        """
        Reset rate limit for a specific user or IP (admin function)
        
        Args:
            wallet_address: Wallet address to reset
            client_ip: IP address to reset
        """
        keys_to_delete = []
        
        if wallet_address:
            keys_to_delete.extend([
                f"{self.config.KEY_PREFIX}:premium:{wallet_address}",
                f"{self.config.KEY_PREFIX}:user:{wallet_address}"
            ])
        
        if client_ip:
            keys_to_delete.append(f"{self.config.KEY_PREFIX}:guest:{client_ip}")
        
        for key in keys_to_delete:
            try:
                await self.redis.delete(key)
                self.logger.info(f"Reset rate limit for key: {key}")
            except Exception as e:
                self.logger.error(f"Failed to reset rate limit for key {key}: {str(e)}")
    
    async def get_current_usage(
        self, 
        user_context: UserContext, 
        client_ip: str
    ) -> Tuple[int, int]:
        """
        Get current usage count and limit for a user
        
        Returns:
            Tuple of (current_count, limit)
        """
        try:
            key = self._get_rate_limit_key(user_context, client_ip)
            limit, _ = self._get_rate_limit_config(user_context)
            
            current_count = await self.redis.get(key)
            if current_count is None:
                return 0, limit
            
            return int(current_count), limit
            
        except Exception as e:
            self.logger.error(f"Error getting current usage: {str(e)}")
            return 0, 0
