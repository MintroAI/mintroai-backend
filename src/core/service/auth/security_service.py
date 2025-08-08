import secrets
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException, status

from src.core.logger.logger import get_logger
from src.core.service.auth.cache.audit_store import AuthAuditStore
from src.core.service.auth.models.audit import (
    AuthAuditLog,
    AuthEventType,
    AuthEventStatus,
    AuthEventContext
)
from src.core.service.auth.models.session import DeviceInfo
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.protocols.base import BlockchainProtocol
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class SecurityService:
    """Service for handling security-related operations across multiple blockchain protocols"""

    def __init__(
        self,
        audit_store: AuthAuditStore,
        signature_service: MultiProtocolSignatureService
    ):
        self.audit_store = audit_store
        self.multi_signature_service = signature_service
        self.jwt_secret_length = settings.JWT_SECRET_LENGTH

    def generate_secure_secret(self) -> str:
        """Generate a cryptographically secure random secret"""
        return secrets.token_urlsafe(self.jwt_secret_length)

    async def verify_sensitive_operation(
        self,
        wallet_address: str,
        signature: str,
        message: str,
        device_info: DeviceInfo,
        operation_type: str,
        protocol: BlockchainProtocol = BlockchainProtocol.EVM,
        session_id: Optional[UUID] = None,
        **kwargs
    ) -> bool:
        """
        Verify signature for sensitive operations across multiple blockchain protocols
        Returns True if verification successful, False otherwise
        """
        try:
            # Check if account is locked
            is_locked = await self.audit_store.check_account_locked(
                wallet_address,
                device_info.ip_address
            )
            if is_locked:
                await self._log_blocked_attempt(
                    wallet_address,
                    device_info,
                    operation_type,
                    session_id,
                    "Account is locked"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is locked due to too many failed attempts"
                )

            # Verify signature using multi-protocol service
            try:
                is_valid, error = await self.multi_signature_service.verify_signature(
                    protocol=protocol,
                    address=wallet_address,
                    message=message,
                    signature=signature,
                    **kwargs
                )
                if not is_valid:
                    raise ValueError(error or "Invalid signature")
                # Log successful verification
                await self._log_successful_operation(
                    wallet_address,
                    device_info,
                    operation_type,
                    session_id
                )

                # Reset failed attempts on success
                await self.audit_store.reset_failed_attempts(
                    wallet_address,
                    device_info.ip_address
                )

                return True

            except ValueError as e:
                # Log failed verification
                await self._log_failed_operation(
                    wallet_address,
                    device_info,
                    operation_type,
                    session_id,
                    str(e)
                )
                return False

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Failed to verify sensitive operation",
                extra={
                    "wallet_address": wallet_address,
                    "operation_type": operation_type,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify operation"
            )

    async def _log_successful_operation(
        self,
        wallet_address: str,
        device_info: DeviceInfo,
        operation_type: str,
        session_id: Optional[UUID] = None
    ) -> None:
        """Log successful sensitive operation"""
        log = AuthAuditLog.create(
            event_type=AuthEventType.SENSITIVE_OPERATION,
            status=AuthEventStatus.SUCCESS,
            wallet_address=wallet_address,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            device_id=device_info.device_id,
            session_id=session_id,
            operation_type=operation_type
        )
        await self.audit_store.add_log(log)

    async def _log_failed_operation(
        self,
        wallet_address: str,
        device_info: DeviceInfo,
        operation_type: str,
        session_id: Optional[UUID] = None,
        failure_reason: str = None
    ) -> None:
        """Log failed sensitive operation"""
        log = AuthAuditLog.create(
            event_type=AuthEventType.SENSITIVE_OPERATION,
            status=AuthEventStatus.FAILURE,
            wallet_address=wallet_address,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            device_id=device_info.device_id,
            session_id=session_id,
            operation_type=operation_type,
            failure_reason=failure_reason
        )
        await self.audit_store.add_log(log)

    async def _log_blocked_attempt(
        self,
        wallet_address: str,
        device_info: DeviceInfo,
        operation_type: str,
        session_id: Optional[UUID] = None,
        failure_reason: str = None
    ) -> None:
        """Log blocked operation attempt"""
        log = AuthAuditLog.create(
            event_type=AuthEventType.SENSITIVE_OPERATION,
            status=AuthEventStatus.BLOCKED,
            wallet_address=wallet_address,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            device_id=device_info.device_id,
            session_id=session_id,
            operation_type=operation_type,
            failure_reason=failure_reason
        )
        await self.audit_store.add_log(log)