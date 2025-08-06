from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import HTTPException, status

from src.core.logger.logger import get_logger
from src.core.service.auth.cache.session_store import SessionStore
from src.core.service.auth.models.session import UserSession, DeviceInfo, SessionStatus
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class UserSessionService:
    """Service for managing user sessions"""

    def __init__(self, session_store: SessionStore):
        self.session_store = session_store
        self.session_inactivity_minutes = settings.SESSION_INACTIVITY_MINUTES

    async def create_session(
        self,
        wallet_address: str,
        device_info: DeviceInfo
    ) -> UserSession:
        """Create a new session for a user"""
        try:
            # Check for existing sessions from same device
            existing_sessions = await self.session_store.get_user_sessions(wallet_address)
            for session in existing_sessions:
                if (
                    session.is_active and
                    session.device_info.device_id == device_info.device_id
                ):
                    # Invalidate old session from same device
                    session.invalidate("New login from same device")
                    await self.session_store.update_session(session)

            # Create new session
            session = UserSession(
                wallet_address=wallet_address,
                device_info=device_info
            )
            await self.session_store.create_session(session)

            logger.info(
                "New session created",
                extra={
                    "session_id": str(session.id),
                    "wallet_address": wallet_address,
                    "device_info": device_info.model_dump()
                }
            )

            return session

        except Exception as e:
            logger.error(
                "Failed to create session",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create session"
            )

    async def get_session(self, session_id: UUID) -> UserSession:
        """Get a session by ID"""
        try:
            session = await self.session_store.get_session(session_id)
            
            if not session:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Session not found"
                )

            return session

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to get session",
                extra={
                    "session_id": str(session_id),
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get session"
            )

    async def update_session_activity(
        self,
        session_id: UUID,
        device_info: Optional[DeviceInfo] = None
    ) -> UserSession:
        """Update session last activity time and optionally device info"""
        try:
            session = await self.get_session(session_id)

            if not session.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session is not active"
                )

            # Check for session timeout
            timeout = datetime.now(timezone.utc) - timedelta(
                minutes=self.session_inactivity_minutes
            )
            if session.last_active_at < timeout:
                session.invalidate("Session timeout")
                await self.session_store.update_session(session)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has timed out"
                )

            # Update session
            session.update_activity()
            if device_info:
                session.device_info = device_info
            await self.session_store.update_session(session)

            return session

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to update session activity",
                extra={
                    "session_id": str(session_id),
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update session"
            )

    async def get_user_sessions(self, wallet_address: str) -> List[UserSession]:
        """Get all sessions for a user"""
        try:
            return await self.session_store.get_user_sessions(wallet_address)

        except Exception as e:
            logger.error(
                "Failed to get user sessions",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get user sessions"
            )

    async def invalidate_session(
        self,
        session_id: UUID,
        reason: str
    ) -> UserSession:
        """Invalidate a specific session"""
        try:
            session = await self.get_session(session_id)

            if not session.is_active:
                return session

            session.invalidate(reason)
            await self.session_store.update_session(session)

            return session

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to invalidate session",
                extra={
                    "session_id": str(session_id),
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to invalidate session"
            )

    async def invalidate_user_sessions(
        self,
        wallet_address: str,
        reason: str,
        exclude_session_id: Optional[UUID] = None
    ) -> None:
        """Invalidate all sessions for a user, optionally excluding one session"""
        try:
            await self.session_store.invalidate_user_sessions(
                wallet_address,
                reason,
                exclude_session_id
            )

        except Exception as e:
            logger.error(
                "Failed to invalidate user sessions",
                extra={
                    "wallet_address": wallet_address,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to invalidate user sessions"
            )