"""
EVM (Ethereum Virtual Machine) Protocol implementation for wallet verification and authentication.
This module provides EVM-specific authentication functionality for Ethereum and compatible chains.
"""

import binascii
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

from eth_account.messages import encode_defunct
from eth_account import Account
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3

from src.core.service.auth.protocols.base import WalletVerifier, ProtocolConfig, BlockchainProtocol
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class EVMConfig(ProtocolConfig):
    """EVM-specific configuration"""
    chain_id: int = 1  # Ethereum mainnet by default
    
    def __init__(self, **data):
        super().__init__(**data)
        self.protocol = BlockchainProtocol.EVM


class EVMVerifier(WalletVerifier):
    """EVM Protocol wallet verifier implementation"""
    
    def __init__(self, config: EVMConfig):
        super().__init__(config)
        self.config: EVMConfig = config
        self._connection_established = True  # EVM doesn't require external connections
    
    async def initialize(self) -> None:
        """Initialize EVM verifier (no external connections needed)"""
        self._connection_established = True
        self.logger.info(
            f"EVM verifier initialized for chain_id {self.config.chain_id}",
            extra={
                "protocol": "evm",
                "chain_id": self.config.chain_id,
                "network_id": self.config.network_id
            }
        )
    
    def validate_address(self, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate EVM address format (Ethereum-style addresses)
        
        Args:
            address: The Ethereum address to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            if not address or not isinstance(address, str):
                return False, "Address must be a non-empty string"
            
            address = address.strip()
            
            # Check basic format
            if not address.startswith("0x"):
                return False, "EVM address must start with '0x'"
            
            if len(address) != 42:  # 0x + 40 hex characters
                return False, "EVM address must be 42 characters long"
            
            # Validate hex characters
            try:
                int(address[2:], 16)
            except ValueError:
                return False, "EVM address contains invalid hex characters"
            
            # Try to convert to checksum address (validates format)
            try:
                Web3.to_checksum_address(address.lower())
            except ValueError as e:
                return False, f"Invalid EVM address format: {str(e)}"
            
            self.logger.debug(f"Validated EVM address: {address}")
            return True, None
            
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
        Verify EVM signature using Ethereum's message signing standard
        
        Args:
            address: The Ethereum address that claims to have signed
            message: The original message that was signed
            signature: The signature to verify (hex string)
            **kwargs: Additional parameters (unused for EVM)
        """
        try:
            # Validate address first
            is_valid_address, addr_error = self.validate_address(address)
            if not is_valid_address:
                return False, f"Invalid address: {addr_error}"
            
            # Convert address to checksum format
            try:
                checksum_address = self._to_checksum_address(address)
            except ValueError as e:
                error_msg = "Invalid Ethereum address format"
                self.logger.error(
                    error_msg,
                    extra={
                        "wallet_address": address,
                        "error": str(e)
                    }
                )
                return False, error_msg
            
            # Convert signature to bytes
            try:
                signature_bytes = self._parse_signature(signature)
            except ValueError as e:
                error_msg = "Invalid signature format"
                self.logger.error(
                    error_msg,
                    extra={
                        "wallet_address": address,
                        "error": str(e)
                    }
                )
                return False, error_msg
            
            # Create signable message
            signable_message = self._create_signable_message(message)
            
            # Recover the address from the signature
            try:
                recovered_address = Account.recover_message(signable_message, signature=signature_bytes)
            except (ValueError, binascii.Error) as e:
                error_msg = "Invalid signature - could not recover address"
                self.logger.error(
                    error_msg,
                    extra={
                        "wallet_address": address,
                        "error": str(e)
                    }
                )
                return False, error_msg
            
            # Compare addresses
            is_valid = recovered_address.lower() == checksum_address.lower()
            
            if is_valid:
                self.logger.info(
                    f"EVM signature verified successfully for {address}",
                    extra={
                        "protocol": "evm",
                        "wallet_address": address,
                        "chain_id": self.config.chain_id
                    }
                )
                return True, None
            else:
                error_msg = "Recovered address does not match claimed address"
                self.logger.warning(
                    error_msg,
                    extra={
                        "wallet_address": address,
                        "recovered_address": recovered_address,
                        "protocol": "evm"
                    }
                )
                return False, error_msg
                
        except Exception as e:
            error_msg = f"EVM signature verification error: {str(e)}"
            self.logger.error(
                error_msg,
                extra={
                    "protocol": "evm",
                    "wallet_address": address,
                    "error": str(e)
                }
            )
            return False, error_msg
    
    def create_challenge_message(self, nonce: str, **kwargs) -> str:
        """Create EVM-specific challenge message"""
        timestamp = datetime.now(timezone.utc).isoformat()
        
        message_parts = [
            "Sign in to MintroAI",
            f"Chain ID: {self.config.chain_id}",
            f"Nonce: {nonce}",
            f"Timestamp: {timestamp}"
        ]
        
        return "\n".join(message_parts)
    
    async def get_account_info(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Get EVM account information (basic info since we don't have web3 provider)
        
        Args:
            address: The Ethereum address to query
            
        Returns:
            Optional[Dict[str, Any]]: Basic account information
        """
        try:
            # Validate address first
            is_valid, error = self.validate_address(address)
            if not is_valid:
                self.logger.debug(f"Invalid EVM address for account info: {address}")
                return None
            
            # Return basic info (we'd need a web3 provider for balance, nonce, etc.)
            return {
                "address": Web3.to_checksum_address(address.lower()),
                "chain_id": self.config.chain_id,
                "network_id": self.config.network_id,
                "protocol": "evm"
            }
            
        except Exception as e:
            self.logger.error(f"Error getting EVM account info for {address}: {str(e)}")
            return None
    
    def _to_checksum_address(self, address: str) -> ChecksumAddress:
        """Convert address to checksum format"""
        try:
            return Web3.to_checksum_address(address.lower())
        except ValueError as e:
            logger.error(str(e), extra={"address": address})
            raise ValueError("Invalid Ethereum address format") from e
    
    def _create_signable_message(self, message: str) -> bytes:
        """Create a signable message using Ethereum's standard format"""
        return encode_defunct(text=message)
    
    def _parse_signature(self, signature: str) -> HexBytes:
        """Parse signature string to HexBytes"""
        try:
            if isinstance(signature, str) and signature.startswith("0x"):
                return HexBytes(signature)
            elif isinstance(signature, str):
                return HexBytes("0x" + signature)
            else:
                return HexBytes(signature)
        except (ValueError, binascii.Error) as e:
            raise ValueError(f"Invalid signature format: {str(e)}") from e


def create_evm_verifier(
    network_id: str = "mainnet",
    chain_id: int = 1
) -> EVMVerifier:
    """Factory function to create an EVM verifier with default configuration"""
    
    config = EVMConfig(
        protocol=BlockchainProtocol.EVM,
        network_id=network_id,
        chain_id=chain_id,
        enabled=True
    )
    
    return EVMVerifier(config)