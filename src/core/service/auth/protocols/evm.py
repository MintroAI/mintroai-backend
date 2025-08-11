"""
EVM Protocol implementation for wallet verification and authentication.
This module provides EVM-specific authentication functionality for Ethereum and compatible chains.
"""

import re
from typing import Tuple, Optional, Dict, Any

from src.core.service.auth.protocols.base import WalletVerifier, ProtocolConfig, BlockchainProtocol
from src.core.service.auth.signature_verification import SignatureVerificationService
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class EVMConfig(ProtocolConfig):
    """EVM-specific configuration"""
    chain_id: int
    rpc_url: Optional[str] = None
    
    def __init__(self, **data):
        super().__init__(**data)
        self.protocol = BlockchainProtocol.EVM


class EVMVerifier(WalletVerifier):
    """EVM Protocol wallet verifier implementation"""
    
    def __init__(self, config: EVMConfig):
        super().__init__(config)
        self.config: EVMConfig = config
        self.signature_service = SignatureVerificationService()
        self.chain_id = config.chain_id
        
        # EVM address validation pattern
        self.address_pattern = re.compile(r'^0x[a-fA-F0-9]{40}$')
    
    async def initialize(self) -> None:
        """Initialize EVM verifier (no special initialization needed)"""
        self.logger.info(
            f"EVM verifier initialized for {self.config.network_id}",
            extra={
                "protocol": "evm",
                "network_id": self.config.network_id,
                "chain_id": self.chain_id
            }
        )
    
    def validate_address(self, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate EVM address format
        
        EVM addresses are 42 characters long (including 0x prefix) and contain only hex characters
        """
        try:
            if not address or not isinstance(address, str):
                return False, "Address must be a non-empty string"
            
            address = address.strip()
            
            # Check basic format
            if not self.address_pattern.match(address):
                return False, "Invalid EVM address format (must be 0x followed by 40 hex characters)"
            
            # Additional validation using Web3 checksum (handled by SignatureVerificationService)
            try:
                from web3 import Web3
                Web3.to_checksum_address(address.lower())
                self.logger.debug(f"Validated EVM address: {address}")
                return True, None
            except ValueError as e:
                return False, f"Invalid EVM address: {str(e)}"
                
        except Exception as e:
            self.logger.error(f"Error validating EVM address {address}: {str(e)}")
            return False, f"Validation error: {str(e)}"
    
    async def verify_signature(
        self,
        address: str,
        message: str,
        signature: str,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify EVM signature using eth-account
        
        Args:
            address: EVM address that claims to have signed
            message: Original message that was signed
            signature: Hex-encoded signature
        """
        try:
            # Validate address first
            is_valid_address, addr_error = self.validate_address(address)
            if not is_valid_address:
                return False, f"Invalid address: {addr_error}"
            
            # Use existing signature verification service
            is_valid, error = self.signature_service.verify_signature(
                claimed_address=address,
                signature=signature,
                message=message
            )
            
            if is_valid:
                self.logger.info(
                    f"EVM signature verified successfully for {address}",
                    extra={
                        "protocol": "evm",
                        "address": address,
                        "network_id": self.config.network_id,
                        "chain_id": self.chain_id
                    }
                )
                return True, None
            else:
                self.logger.warning(
                    f"EVM signature verification failed for {address}",
                    extra={
                        "protocol": "evm",
                        "address": address,
                        "error": error
                    }
                )
                return False, error
                
        except Exception as e:
            error_msg = f"EVM signature verification error: {str(e)}"
            self.logger.error(
                error_msg,
                extra={
                    "protocol": "evm",
                    "address": address,
                    "error": str(e)
                }
            )
            return False, error_msg
    
    def create_challenge_message(self, nonce: str, **kwargs) -> str:
        """Create EVM-specific challenge message"""
        return f"Sign in to MintroAI\nNonce: {nonce}"
    
    async def get_account_info(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Get EVM account information
        
        Note: This is a placeholder. In a full implementation, you would
        query the blockchain for account balance, nonce, etc.
        """
        try:
            # Validate address first
            is_valid, error = self.validate_address(address)
            if not is_valid:
                return None
            
            return {
                "address": address,
                "network_id": self.config.network_id,
                "chain_id": self.chain_id,
                "protocol": "evm"
            }
            
        except Exception as e:
            self.logger.error(f"Error getting EVM account info for {address}: {str(e)}")
            return None
    
    def generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce for EVM challenges"""
        import secrets
        return "0x" + secrets.token_hex(32)


def create_evm_verifier(
    network_id: str = "mainnet",
    chain_id: int = 1,
    rpc_url: Optional[str] = None
) -> EVMVerifier:
    """Factory function to create an EVM verifier with default configuration"""
    
    config = EVMConfig(
        protocol=BlockchainProtocol.EVM,
        network_id=network_id,
        chain_id=chain_id,
        rpc_url=rpc_url,
        enabled=True
    )
    
    return EVMVerifier(config)
