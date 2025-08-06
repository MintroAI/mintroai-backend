import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID

from redis.asyncio import Redis

from src.core.logger.logger import get_logger
from src.core.service.auth.models.session import UserSession, DeviceInfo
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class SessionStore:
    """Redis-based store for managing user sessions"""

    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.session_key_prefix = "session:"
        self.user_sessions_key_prefix = "user_sessions:"

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

    def _serialize_session(self, session: UserSession) -> Dict:
        """Convert UserSession to JSON-serializable dict"""
        data = session.model_dump()
        data["id"] = self._serialize_uuid(data["id"])
        data["created_at"] = self._serialize_datetime(data["created_at"])
        data["last_active_at"] = self._serialize_datetime(data["last_active_at"])
        if data["invalidated_at"]:
            data["invalidated_at"] = self._serialize_datetime(data["invalidated_at"])
        return data

    def _deserialize_session(self, data: Dict) -> UserSession:
        """Convert JSON dict to UserSession"""
        data["id"] = self._deserialize_uuid(data["id"])
        data["created_at"] = self._deserialize_datetime(data["created_at"])
        data["last_active_at"] = self._deserialize_datetime(data["last_active_at"])
        if data["invalidated_at"]:
            data["invalidated_at"] = self._deserialize_datetime(data["invalidated_at"])
        return UserSession(**data)

    async def create_session(self, session: UserSession) -> None:
        """Store a new user session"""
        try:
            # Store session by ID
            session_key = f"{self.session_key_prefix}{session.id}"
            await self.redis.set(
                session_key,
                json.dumps(self._serialize_session(session))
            )

            # Add session ID to user's session list
            user_sessions_key = f"{self.user_sessions_key_prefix}{session.wallet_address}"
            await self.redis.sadd(user_sessions_key, str(session.id))

            logger.info(
                "Session created",
                extra={
                    "session_id": str(session.id),
                    "wallet_address": session.wallet_address,
                    "device_info": session.device_info.model_dump()
                }
            )

        except Exception as e:
            logger.error(
                "Failed to create session",
                extra={
                    "session_id": str(session.id),
                    "wallet_address": session.wallet_address,
                    "error": str(e)
                }
            )
            raise

    async def get_session(self, session_id: UUID) -> Optional[UserSession]:
        """Retrieve a session by ID"""
        try:
            session_key = f"{self.session_key_prefix}{session_id}"
            data = await self.redis.get(session_key)
            
            if not data:
                return None

            session = self._deserialize_session(json.loads(data))
            return session

        except Exception as e:
            logger.error(
                "Failed to get session",
                extra={
                    "session_id": str(session_id),
                    "error": str(e)
                }
            )
            raise

    async def update_session(self, session: UserSession) -> None:
        """Update an existing session"""
        try:
            session_key = f"{self.session_key_prefix}{session.id}"
            exists = await self.redis.exists(session_key)
            
            if not exists:
                raise ValueError(f"Session {session.id} not found")

            await self.redis.set(
                session_key,
                json.dumps(self._serialize_session(session))
            )

            logger.info(
                "Session updated",
                extra={
                    "session_id": str(session.id),
                    "wallet_address": session.wallet_address,
                    "status": session.status
                }
            )

        except Exception as e:
            logger.error(
                "Failed to update session",
                extra={
                    "session_id": str(session.id),
                    "wallet_address": session.wallet_address,
                    "error": str(e)
                }
            )
            raise

    async def get_user_sessions(self, wallet_address: str) -> List[UserSession]:
        """Get all sessions for a user"""
        try:
            # Get session IDs for user
            user_sessions_key = f"{self.user_sessions_key_prefix}{wallet_address}"
            session_ids = await self.redis.smembers(user_sessions_key)

            if not session_ids:
                return []

            # Get session data for each ID
            sessions = []
            for session_id in session_ids:
                session = await self.get_session(UUID(session_id))
                if session:
                    sessions.append(session)

            return sessions

        except Exception as e:
            logger.error(
                "Failed to get user sessions",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise

    async def invalidate_user_sessions(
        self,
        wallet_address: str,
        reason: str,
        exclude_session_id: Optional[UUID] = None
    ) -> None:
        """Invalidate all sessions for a user, optionally excluding one session"""
        try:
            sessions = await self.get_user_sessions(wallet_address)
            
            for session in sessions:
                if exclude_session_id and session.id == exclude_session_id:
                    continue
                    
                if session.is_active:
                    session.invalidate(reason)
                    await self.update_session(session)

            logger.info(
                "User sessions invalidated",
                extra={
                    "wallet_address": wallet_address,
                    "reason": reason,
                    "excluded_session": str(exclude_session_id) if exclude_session_id else None
                }
            )

        except Exception as e:
            logger.error(
                "Failed to invalidate user sessions",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise