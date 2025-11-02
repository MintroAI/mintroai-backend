import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from src.core.service.auth.models.challenge import Challenge, ChallengeStatus
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.protocols.base import BlockchainProtocol
from src.core.logger.logger import logger
from src.infra.config.settings import settings


class ChallengeService:
    """Service for managing authentication challenges"""
    
    CHALLENGE_EXPIRY_SECONDS = settings.CHALLENGE_EXPIRY_SECONDS
    NONCE_BYTES = 32  # 256 bits of entropy
    
    def __init__(
        self, 
        challenge_store, 
        signature_service: Optional[MultiProtocolSignatureService] = None,
        user_repository = None
    ):
        self.store = challenge_store
        self.signature_service = signature_service or MultiProtocolSignatureService()
        self.user_repository = user_repository
    
    def _generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce"""
        return "0x" + secrets.token_hex(self.NONCE_BYTES)
    
    async def create_challenge(self, wallet_address: str, protocol: BlockchainProtocol) -> Challenge:
        """Create a new challenge for wallet authentication"""
        # Validate wallet address format using protocol-specific validation
        is_valid, error_msg = self.signature_service.validate_address(wallet_address, protocol)
        if not is_valid:
            raise ValueError(f"Invalid {protocol.value} address: {error_msg}")
            
        # Check for existing challenge
        existing = await self.get_active_challenge(wallet_address)
        if existing:
            logger.info(f"Active challenge exists for {wallet_address}")
            return existing
            
        # Generate new challenge
        nonce = self._generate_nonce()
        message = self.signature_service.create_challenge_message(
            nonce, 
            protocol,
            account_id=wallet_address if protocol == BlockchainProtocol.NEAR else None
        )
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.CHALLENGE_EXPIRY_SECONDS)
        
        challenge = Challenge(
            nonce=nonce,
            wallet_address=wallet_address,
            protocol=protocol.value,
            expires_at=expires_at,
            message=message
        )
        
        # Store challenge
        await self.store.save_challenge(challenge)
        logger.info(f"Created new challenge for {wallet_address}")
        
        # Log to database (non-blocking)
        if self.user_repository:
            try:
                await self.user_repository.update_user_challenge(wallet_address, protocol.value)
            except Exception as db_error:
                logger.error(
                    f"Failed to log challenge to database: {db_error}",
                    extra={
                        "wallet_address": wallet_address,
                        "protocol": protocol.value
                    }
                )
        
        return challenge
    
    async def get_active_challenge(self, wallet_address: str) -> Optional[Challenge]:
        """Get active challenge for wallet address if exists"""
        challenge = await self.store.get_challenge(wallet_address)
        
        if not challenge:
            return None
            
        # Check if expired
        if datetime.now(timezone.utc) > challenge.expires_at:
            challenge.status = ChallengeStatus.EXPIRED
            await self.store.save_challenge(challenge) # Update status in store
            return None
            
        return challenge if challenge.status == ChallengeStatus.PENDING else None
    
    async def verify_challenge(
        self, 
        wallet_address: str, 
        signature: str, 
        protocol: BlockchainProtocol,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a challenge signature
        
        Args:
            wallet_address: The wallet address that claims to have signed the challenge
            signature: The signature to verify
            protocol: The blockchain protocol
            **kwargs: Protocol-specific parameters (e.g., public_key for NEAR)
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Get active challenge
        challenge = await self.get_active_challenge(wallet_address)
        if not challenge:
            error_msg = "No active challenge found"
            logger.error(
                error_msg,
                extra={"wallet_address": wallet_address, "protocol": protocol.value}
            )
            return False, error_msg
        
        # Verify protocol matches
        if challenge.protocol != protocol.value:
            error_msg = f"Protocol mismatch: challenge created for {challenge.protocol}, verification requested for {protocol.value}"
            logger.error(error_msg, extra={"wallet_address": wallet_address})
            return False, error_msg
        
        # Verify signature using multi-protocol service
        is_valid, error = await self.signature_service.verify_signature(
            address=wallet_address,
            message=challenge.message,
            signature=signature,
            protocol=protocol,
            **kwargs
        )
        
        if not is_valid:
            # Mark challenge as invalid
            challenge.status = ChallengeStatus.INVALID
            await self.store.save_challenge(challenge)
            logger.warning(
                f"Challenge verification failed for {wallet_address}",
                extra={"protocol": protocol.value, "error": error}
            )
            return False, error
        
        # Mark challenge as verified
        challenge.status = ChallengeStatus.VERIFIED
        await self.store.save_challenge(challenge)
        
        logger.info(
            f"Challenge verified successfully for {wallet_address}",
            extra={"protocol": protocol.value}
        )
        
        # Log successful login to database (non-blocking)
        if self.user_repository:
            try:
                await self.user_repository.update_user_login(wallet_address, protocol.value)
            except Exception as db_error:
                logger.error(
                    f"Failed to log user login to database: {db_error}",
                    extra={
                        "wallet_address": wallet_address,
                        "protocol": protocol.value
                    }
                )
        
        return True, None
    
    async def invalidate_challenge(self, wallet_address: str, status: ChallengeStatus) -> None:
        """Invalidate challenge for wallet address"""
        challenge = await self.store.get_challenge(wallet_address)
        if challenge:
            challenge.status = status
            await self.store.save_challenge(challenge)
            logger.info(f"Invalidated challenge for {wallet_address} with status {status}")