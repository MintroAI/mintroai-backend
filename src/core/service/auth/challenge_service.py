import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from src.core.service.auth.models.challenge import Challenge, ChallengeStatus
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.protocols.base import BlockchainProtocol
from src.core.logger.logger import logger
from src.infra.config.settings import settings


class ChallengeService:
    """Service for managing authentication challenges across multiple blockchain protocols"""
    
    CHALLENGE_EXPIRY_SECONDS = settings.CHALLENGE_EXPIRY_SECONDS
    NONCE_BYTES = 32  # 256 bits of entropy
    
    def __init__(self, challenge_store, signature_service: Optional[MultiProtocolSignatureService] = None):
        self.store = challenge_store
        self.multi_signature_service = signature_service or MultiProtocolSignatureService()
    
    def _generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce"""
        return "0x" + secrets.token_hex(self.NONCE_BYTES)
    
    async def create_challenge(
        self, 
        wallet_address: str, 
        protocol: BlockchainProtocol = BlockchainProtocol.EVM
    ) -> Challenge:
        """Create a new challenge for wallet authentication"""
        # Validate address using protocol-specific validation
        is_valid, error = self.multi_signature_service.validate_address(protocol, wallet_address)
        if not is_valid:
            raise ValueError(f"Invalid {protocol.value} address: {error}")
        
        # Normalize address (lowercase for consistency)
        wallet_address = wallet_address.lower()
            
        # Check for existing challenge
        existing = await self.get_active_challenge(wallet_address)
        if existing:
            logger.info(f"Active challenge exists for {wallet_address}")
            return existing
            
        # Generate new challenge
        nonce = self._generate_nonce()
        
        # Create protocol-specific challenge message
        message = self.multi_signature_service.create_challenge_message(protocol, nonce)
        if not message:
            raise ValueError(f"Failed to create challenge message for protocol {protocol.value}")
        
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.CHALLENGE_EXPIRY_SECONDS)
        
        challenge = Challenge(
            nonce=nonce,
            wallet_address=wallet_address,
            expires_at=expires_at,
            message=message,
            protocol=protocol.value  # Store protocol in challenge
        )
        
        # Store challenge
        await self.store.save_challenge(challenge)
        logger.info(
            f"Created new challenge for {wallet_address}",
            extra={
                "protocol": protocol.value,
                "wallet_address": wallet_address
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
        protocol: Optional[BlockchainProtocol] = None,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a challenge signature
        
        Args:
            wallet_address: The wallet address that claims to have signed the challenge
            signature: The signature to verify
            protocol: The blockchain protocol (if not provided, will try to detect from challenge)
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
                extra={"wallet_address": wallet_address}
            )
            return False, error_msg
        
        # Determine protocol - use provided protocol or try to get from challenge
        if protocol is None:
            if hasattr(challenge, 'protocol') and challenge.protocol:
                try:
                    protocol = BlockchainProtocol(challenge.protocol)
                except ValueError:
                    protocol = BlockchainProtocol.EVM  # fallback to EVM
            else:
                protocol = BlockchainProtocol.EVM  # default to EVM for backward compatibility
        
        # Verify signature using multi-protocol service
        is_valid, error = await self.multi_signature_service.verify_signature(
            protocol=protocol,
            address=wallet_address,
            message=challenge.message,
            signature=signature,
            **kwargs
        )
        
        if not is_valid:
            # Mark challenge as invalid
            challenge.status = ChallengeStatus.INVALID
            await self.store.save_challenge(challenge)
            logger.warning(
                "Challenge verification failed",
                extra={
                    "wallet_address": wallet_address,
                    "protocol": protocol.value,
                    "error": error
                }
            )
            return False, error
        
        # Mark challenge as verified
        challenge.status = ChallengeStatus.VERIFIED
        await self.store.save_challenge(challenge)
        
        logger.info(
            "Challenge verified successfully",
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