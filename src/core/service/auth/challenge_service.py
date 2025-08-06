import secrets
from datetime import datetime, timedelta
from typing import Optional

from src.core.service.auth.models.challenge import Challenge, ChallengeStatus
from src.core.logger.logger import logger


class ChallengeService:
    """Service for managing authentication challenges"""
    
    CHALLENGE_EXPIRY_SECONDS = 300  # 5 minutes
    NONCE_BYTES = 32  # 256 bits of entropy
    
    def __init__(self, challenge_store):
        self.store = challenge_store
    
    def _generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce"""
        return "0x" + secrets.token_hex(self.NONCE_BYTES)
    
    def _create_challenge_message(self, nonce: str) -> str:
        """Create a standard message format for signing"""
        return f"Sign in to MintroAI\nNonce: {nonce}"
    
    async def create_challenge(self, wallet_address: str) -> Challenge:
        """Create a new challenge for wallet authentication"""
        # Validate wallet address format
        wallet_address = wallet_address.lower()
        if not wallet_address.startswith("0x") or len(wallet_address) != 42:
            raise ValueError("Invalid wallet address format")
        
        # Validate hex characters
        try:
            int(wallet_address[2:], 16)
        except ValueError:
            raise ValueError("Invalid wallet address format")
            
        # Check for existing challenge
        existing = await self.get_active_challenge(wallet_address)
        if existing:
            logger.info(f"Active challenge exists for {wallet_address}")
            return existing
            
        # Generate new challenge
        nonce = self._generate_nonce()
        message = self._create_challenge_message(nonce)
        expires_at = datetime.utcnow() + timedelta(seconds=self.CHALLENGE_EXPIRY_SECONDS)
        
        challenge = Challenge(
            nonce=nonce,
            wallet_address=wallet_address,
            expires_at=expires_at,
            message=message
        )
        
        # Store challenge
        await self.store.save_challenge(challenge)
        logger.info(f"Created new challenge for {wallet_address}")
        
        return challenge
    
    async def get_active_challenge(self, wallet_address: str) -> Optional[Challenge]:
        """Get active challenge for wallet address if exists"""
        challenge = await self.store.get_challenge(wallet_address)
        
        if not challenge:
            return None
            
        # Check if expired
        if datetime.utcnow() > challenge.expires_at:
            challenge.status = ChallengeStatus.EXPIRED
            await self.store.save_challenge(challenge)
            return None
            
        return challenge if challenge.status == ChallengeStatus.PENDING else None
    
    async def invalidate_challenge(self, wallet_address: str, status: ChallengeStatus) -> None:
        """Invalidate challenge for wallet address"""
        challenge = await self.store.get_challenge(wallet_address)
        if challenge:
            challenge.status = status
            await self.store.save_challenge(challenge)
            logger.info(f"Invalidated challenge for {wallet_address} with status {status}")