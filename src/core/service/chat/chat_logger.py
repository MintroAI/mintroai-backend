"""
Chat interaction logging service
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional

from src.core.service.chat.models.chat import ChatInteractionLog, ChatMode, UserContext
from src.core.logger.logger import get_logger
from src.infra.config.redis import get_redis

logger = get_logger(__name__)


class ChatLogger:
    """Service for logging chat interactions"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.logger = logger
        self.log_key_prefix = "chat_log"
        self.stats_key_prefix = "chat_stats"
    
    async def log_interaction(
        self,
        session_id: str,
        user_context: UserContext,
        chat_input: str,
        mode: ChatMode,
        response: Dict[str, Any],
        duration: float,
        client_ip: str,
        user_agent: Optional[str] = None
    ):
        """
        Log a chat interaction for audit and analytics
        
        Args:
            session_id: Session identifier
            user_context: User context information
            chat_input: User's input message
            mode: Chat mode (token, vesting, general)
            response: n8n response
            duration: Request duration in seconds
            client_ip: Client IP address
            user_agent: Optional user agent string
        """
        # If Redis is not available, just log to console
        if not self.redis:
            self.logger.info(
                f"Chat interaction (Redis unavailable)",
                extra={
                    "session_id": session_id,
                    "mode": mode.value,
                    "authenticated": user_context.is_authenticated,
                    "duration": duration,
                    "success": "error" not in response
                }
            )
            return
            
        try:
            # Create log entry
            log_entry = ChatInteractionLog(
                timestamp=datetime.utcnow(),
                session_id=session_id,
                wallet_address=user_context.wallet_address,
                is_authenticated=user_context.is_authenticated,
                chat_mode=mode.value,
                message_length=len(chat_input),
                response_success="error" not in response,
                duration_seconds=duration,
                client_ip=client_ip,
                user_agent=user_agent,
                error_message=response.get("error") if "error" in response else None
            )
            
            # Store in Redis with expiry (7 days)
            log_key = f"{self.log_key_prefix}:{session_id}:{datetime.utcnow().timestamp()}"
            await self.redis.setex(
                log_key,
                604800,  # 7 days in seconds
                json.dumps(log_entry.dict(), default=str)
            )
            
            # Update statistics
            await self._update_statistics(user_context, mode, "error" not in response)
            
            self.logger.info(
                f"Chat interaction logged",
                extra={
                    "session_id": session_id,
                    "mode": mode.value,
                    "authenticated": user_context.is_authenticated,
                    "duration": duration,
                    "success": "error" not in response
                }
            )
            
        except Exception as e:
            self.logger.error(
                f"Failed to log chat interaction: {str(e)}",
                extra={
                    "session_id": session_id,
                    "error": str(e)
                }
            )
    
    async def _update_statistics(
        self,
        user_context: UserContext,
        mode: ChatMode,
        success: bool
    ):
        """Update chat statistics"""
        try:
            # Daily statistics key
            today = datetime.utcnow().strftime("%Y-%m-%d")
            
            # Increment total messages
            await self.redis.hincrby(
                f"{self.stats_key_prefix}:{today}",
                "total_messages",
                1
            )
            
            # Increment mode-specific counter
            await self.redis.hincrby(
                f"{self.stats_key_prefix}:{today}",
                f"mode_{mode.value}",
                1
            )
            
            # Increment user type counter
            user_type = "authenticated" if user_context.is_authenticated else "guest"
            await self.redis.hincrby(
                f"{self.stats_key_prefix}:{today}",
                f"user_{user_type}",
                1
            )
            
            # Increment success/error counter
            status = "success" if success else "error"
            await self.redis.hincrby(
                f"{self.stats_key_prefix}:{today}",
                f"status_{status}",
                1
            )
            
            # Set expiry on stats (30 days)
            await self.redis.expire(f"{self.stats_key_prefix}:{today}", 2592000)
            
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {str(e)}")
    
    async def get_user_chat_history(
        self,
        wallet_address: str,
        limit: int = 10
    ) -> list:
        """
        Get chat history for a specific user
        
        Args:
            wallet_address: User's wallet address
            limit: Maximum number of entries to return
            
        Returns:
            List of chat log entries
        """
        try:
            # Search for user's chat logs
            pattern = f"{self.log_key_prefix}:*"
            cursor = 0
            user_logs = []
            
            while len(user_logs) < limit:
                cursor, keys = await self.redis.scan(
                    cursor,
                    match=pattern,
                    count=100
                )
                
                for key in keys:
                    log_data = await self.redis.get(key)
                    if log_data:
                        log_entry = json.loads(log_data)
                        if log_entry.get("wallet_address") == wallet_address:
                            user_logs.append(log_entry)
                            if len(user_logs) >= limit:
                                break
                
                if cursor == 0:
                    break
            
            # Sort by timestamp (newest first)
            user_logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return user_logs[:limit]
            
        except Exception as e:
            self.logger.error(
                f"Failed to get user chat history: {str(e)}",
                extra={"wallet_address": wallet_address}
            )
            return []
    
    async def get_daily_statistics(self, date: Optional[str] = None) -> Dict[str, Any]:
        """
        Get chat statistics for a specific date
        
        Args:
            date: Date in YYYY-MM-DD format (defaults to today)
            
        Returns:
            Dictionary with statistics
        """
        try:
            if not date:
                date = datetime.utcnow().strftime("%Y-%m-%d")
            
            stats_key = f"{self.stats_key_prefix}:{date}"
            stats = await self.redis.hgetall(stats_key)
            
            # Convert byte strings to regular strings and integers
            result = {}
            for key, value in stats.items():
                key_str = key.decode() if isinstance(key, bytes) else key
                value_str = value.decode() if isinstance(value, bytes) else value
                try:
                    result[key_str] = int(value_str)
                except ValueError:
                    result[key_str] = value_str
            
            # Add calculated metrics
            if "total_messages" in result:
                total = result["total_messages"]
                success = result.get("status_success", 0)
                error = result.get("status_error", 0)
                
                if total > 0:
                    result["success_rate"] = round((success / total) * 100, 2)
                    result["error_rate"] = round((error / total) * 100, 2)
            
            result["date"] = date
            
            return result
            
        except Exception as e:
            self.logger.error(
                f"Failed to get daily statistics: {str(e)}",
                extra={"date": date}
            )
            return {"date": date, "error": str(e)}
