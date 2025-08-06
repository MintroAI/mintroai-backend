import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from redis.asyncio import Redis

from src.core.logger.logger import get_logger
from src.core.service.auth.models.audit import AuthAuditLog, AuthEventType, AuthEventStatus
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class AuthAuditStore:
    """Redis-based store for authentication audit logs"""

    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.audit_key_prefix = "audit:log:"
        self.user_audit_key_prefix = "audit:user:"
        self.failed_attempts_key_prefix = "audit:failed_attempts:"
        self.audit_retention_days = settings.AUDIT_LOG_RETENTION_DAYS
        self.max_failed_attempts = settings.MAX_FAILED_AUTH_ATTEMPTS
        self.lockout_minutes = settings.AUTH_LOCKOUT_MINUTES

    def _serialize_datetime(self, dt: datetime) -> str:
        """Convert datetime to ISO format string"""
        return dt.isoformat()

    def _deserialize_datetime(self, dt_str: str) -> datetime:
        """Convert ISO format string to datetime"""
        return datetime.fromisoformat(dt_str)

    def _serialize_uuid(self, uuid: UUID) -> str:
        """Convert UUID to string"""
        return str(uuid)

    def _deserialize_uuid(self, uuid_str: str) -> UUID:
        """Convert string to UUID"""
        return UUID(uuid_str)

    def _serialize_audit_log(self, log: AuthAuditLog) -> Dict:
        """Convert AuthAuditLog to JSON-serializable dict"""
        data = log.model_dump()
        data["id"] = self._serialize_uuid(data["id"])
        data["timestamp"] = self._serialize_datetime(data["timestamp"])
        if data["context"]["session_id"]:
            data["context"]["session_id"] = self._serialize_uuid(
                data["context"]["session_id"]
            )
        return data

    def _deserialize_audit_log(self, data: Dict) -> AuthAuditLog:
        """Convert JSON dict to AuthAuditLog"""
        data["id"] = self._deserialize_uuid(data["id"])
        data["timestamp"] = self._deserialize_datetime(data["timestamp"])
        if data["context"]["session_id"]:
            data["context"]["session_id"] = self._deserialize_uuid(
                data["context"]["session_id"]
            )
        return AuthAuditLog(**data)

    async def add_log(self, log: AuthAuditLog) -> None:
        """Store a new audit log entry"""
        try:
            # Store log by ID
            log_key = f"{self.audit_key_prefix}{log.id}"
            ttl_seconds = max(1, int(timedelta(days=self.audit_retention_days).total_seconds()))
            await self.redis.setex(
                log_key,
                ttl_seconds,
                json.dumps(self._serialize_audit_log(log))
            )

            # Add log ID to user's audit list
            user_audit_key = f"{self.user_audit_key_prefix}{log.wallet_address}"
            await self.redis.lpush(user_audit_key, str(log.id))
            await self.redis.expire(
                user_audit_key,
                ttl_seconds
            )

            # Track failed attempts if applicable
            if log.status == AuthEventStatus.FAILURE:
                await self._track_failed_attempt(
                    log.wallet_address,
                    log.context.ip_address
                )

            logger.info(
                "Audit log created",
                extra={
                    "log_id": str(log.id),
                    "wallet_address": log.wallet_address,
                    "event_type": log.event_type,
                    "status": log.status
                }
            )

        except Exception as e:
            logger.error(
                "Failed to create audit log",
                extra={
                    "log_id": str(log.id),
                    "wallet_address": log.wallet_address,
                    "error": str(e)
                }
            )
            raise

    async def get_user_logs(
        self,
        wallet_address: str,
        limit: Optional[int] = None
    ) -> List[AuthAuditLog]:
        """Get audit logs for a user"""
        try:
            # Get log IDs for user
            user_audit_key = f"{self.user_audit_key_prefix}{wallet_address}"
            log_ids = await self.redis.lrange(user_audit_key, 0, limit or -1)

            if not log_ids:
                return []

            # Get log data for each ID
            logs = []
            for log_id in log_ids:
                log_key = f"{self.audit_key_prefix}{log_id}"
                data = await self.redis.get(log_key)
                if data:
                    logs.append(
                        self._deserialize_audit_log(json.loads(data))
                    )

            return logs

        except Exception as e:
            logger.error(
                "Failed to get user audit logs",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise

    async def _track_failed_attempt(
        self,
        wallet_address: str,
        ip_address: str
    ) -> None:
        """Track failed authentication attempts"""
        key = f"{self.failed_attempts_key_prefix}{wallet_address}:{ip_address}"
        
        # Increment failed attempts counter
        attempts = await self.redis.incr(key)
        
        if attempts == 1:
            # Set expiry on first attempt
            await self.redis.expire(
                key,
                timedelta(minutes=self.lockout_minutes)
            )
        
        if attempts >= self.max_failed_attempts:
            # Create account lockout audit log
            log = AuthAuditLog.create(
                event_type=AuthEventType.ACCOUNT_LOCKED,
                status=AuthEventStatus.BLOCKED,
                wallet_address=wallet_address,
                ip_address=ip_address,
                failure_reason=f"Maximum failed attempts ({attempts}) exceeded"
            )
            await self.add_log(log)

            logger.warning(
                "Account locked due to failed attempts",
                extra={
                    "wallet_address": wallet_address,
                    "ip_address": ip_address,
                    "attempts": attempts
                }
            )

    async def check_account_locked(
        self,
        wallet_address: str,
        ip_address: str
    ) -> bool:
        """Check if an account is locked due to failed attempts"""
        key = f"{self.failed_attempts_key_prefix}{wallet_address}:{ip_address}"
        attempts = await self.redis.get(key)
        
        if attempts and int(attempts) >= self.max_failed_attempts:
            return True
            
        return False

    async def reset_failed_attempts(
        self,
        wallet_address: str,
        ip_address: str
    ) -> None:
        """Reset failed attempts counter on successful authentication"""
        key = f"{self.failed_attempts_key_prefix}{wallet_address}:{ip_address}"
        await self.redis.delete(key)