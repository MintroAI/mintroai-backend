"""
Protocol abstraction layer for multi-chain authentication support.
This module provides the base interface for implementing different blockchain protocols.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Tuple, Optional, Dict, Any
from pydantic import BaseModel

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class BlockchainProtocol(str, Enum):
    """Supported blockchain protocols"""
    EVM = "evm"
    NEAR = "near"


class ProtocolConfig(BaseModel):
    """Base configuration for blockchain protocols"""
    protocol: BlockchainProtocol
    network_id: str  # "mainnet", "testnet", etc.
    enabled: bool = True
    
    class Config:
        use_enum_values = True


class WalletVerifier(ABC):
    """
    Abstract base class for wallet verification across different blockchain protocols.
    Each protocol implementation should inherit from this class.
    """
    
    def __init__(self, config: ProtocolConfig):
        self.config = config
        self.protocol = config.protocol
        self.network_id = config.network_id
        self.logger = get_logger(f"{__name__}.{self.protocol.value}")
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the protocol verifier (e.g., establish network connections)"""
        pass
    
    @abstractmethod
    def validate_address(self, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate address format for this protocol
        
        Args:
            address: The address/account ID to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        pass
    
    @abstractmethod
    async def verify_signature(
        self,
        address: str,
        message: str,
        signature: str,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a signature for this protocol
        
        Args:
            address: The address/account ID that claims to have signed
            message: The original message that was signed
            signature: The signature to verify
            **kwargs: Protocol-specific additional parameters
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        pass
    
    @abstractmethod
    def create_challenge_message(self, nonce: str, **kwargs) -> str:
        """
        Create a protocol-specific challenge message
        
        Args:
            nonce: Unique nonce for the challenge
            **kwargs: Protocol-specific parameters
            
        Returns:
            str: Formatted challenge message
        """
        pass
    
    @abstractmethod
    async def get_account_info(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Get account information from the blockchain
        
        Args:
            address: The address/account ID to query
            
        Returns:
            Optional[Dict[str, Any]]: Account information or None if not found
        """
        pass
    
    def get_protocol_info(self) -> Dict[str, Any]:
        """Get protocol information"""
        return {
            "protocol": self.protocol.value,
            "network_id": self.network_id,
            "enabled": self.config.enabled
        }


class ProtocolRegistry:
    """Registry for managing protocol verifiers"""
    
    def __init__(self):
        self._verifiers: Dict[BlockchainProtocol, WalletVerifier] = {}
        self.logger = get_logger(__name__)
    
    def register(self, verifier: WalletVerifier) -> None:
        """Register a protocol verifier"""
        self._verifiers[verifier.protocol] = verifier
        self.logger.info(f"Registered protocol verifier: {verifier.protocol.value}")
    
    def get_verifier(self, protocol: BlockchainProtocol) -> Optional[WalletVerifier]:
        """Get a protocol verifier by protocol type"""
        return self._verifiers.get(protocol)
    
    def get_supported_protocols(self) -> list[BlockchainProtocol]:
        """Get list of supported protocols"""
        return list(self._verifiers.keys())
    
    async def initialize_all(self) -> None:
        """Initialize all registered verifiers"""
        for protocol, verifier in self._verifiers.items():
            try:
                await verifier.initialize()
                self.logger.info(f"Initialized {protocol.value} verifier")
            except Exception as e:
                self.logger.error(f"Failed to initialize {protocol.value} verifier: {e}")
                raise


# Global protocol registry instance
protocol_registry = ProtocolRegistry()