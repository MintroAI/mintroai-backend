"""
Multi-protocol signature verification service.
This service acts as a facade for different blockchain protocol verifiers.
"""

from typing import Tuple, Optional, Dict, Any

from src.core.service.auth.protocols.base import BlockchainProtocol, protocol_registry, WalletVerifier
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class MultiProtocolSignatureService:
    """
    Multi-protocol signature verification service that delegates to appropriate protocol verifiers.
    This service provides a unified interface for signature verification across different blockchain protocols.
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def _get_verifier(self, protocol: BlockchainProtocol) -> WalletVerifier:
        """Get the appropriate verifier for the given protocol"""
        verifier = protocol_registry.get_verifier(protocol)
        if not verifier:
            supported_protocols = [p.value for p in protocol_registry.get_supported_protocols()]
            raise ValueError(
                f"Protocol '{protocol.value}' is not supported. "
                f"Supported protocols: {supported_protocols}"
            )
        return verifier
    
    def validate_address(self, address: str, protocol: BlockchainProtocol) -> Tuple[bool, Optional[str]]:
        """
        Validate address format for the specified protocol
        
        Args:
            address: The address to validate
            protocol: The blockchain protocol
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            verifier = self._get_verifier(protocol)
            return verifier.validate_address(address)
        except Exception as e:
            error_msg = f"Address validation error for protocol {protocol.value}: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    async def verify_signature(
        self,
        address: str,
        message: str,
        signature: str,
        protocol: BlockchainProtocol,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a signature using the appropriate protocol verifier
        
        Args:
            address: The address that claims to have signed
            message: The original message that was signed
            signature: The signature to verify
            protocol: The blockchain protocol
            **kwargs: Protocol-specific additional parameters
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            verifier = self._get_verifier(protocol)
            
            self.logger.debug(
                f"Verifying signature for protocol {protocol.value}",
                extra={
                    "protocol": protocol.value,
                    "address": address
                }
            )
            
            return await verifier.verify_signature(
                address=address,
                message=message,
                signature=signature,
                **kwargs
            )
            
        except Exception as e:
            error_msg = f"Signature verification error for protocol {protocol.value}: {str(e)}"
            self.logger.error(
                error_msg,
                extra={
                    "protocol": protocol.value,
                    "address": address,
                    "error": str(e)
                }
            )
            return False, error_msg
    
    def create_challenge_message(
        self,
        nonce: str,
        protocol: BlockchainProtocol,
        **kwargs
    ) -> str:
        """
        Create a protocol-specific challenge message
        
        Args:
            nonce: Unique nonce for the challenge
            protocol: The blockchain protocol
            **kwargs: Protocol-specific parameters
            
        Returns:
            str: Formatted challenge message
        """
        try:
            verifier = self._get_verifier(protocol)
            return verifier.create_challenge_message(nonce, **kwargs)
        except Exception as e:
            error_msg = f"Challenge message creation error for protocol {protocol.value}: {str(e)}"
            self.logger.error(error_msg)
            # Fallback to generic message
            return f"Sign in to MintroAI\nNonce: {nonce}"
    
    async def get_account_info(
        self,
        address: str,
        protocol: BlockchainProtocol
    ) -> Optional[Dict[str, Any]]:
        """
        Get account information for the specified protocol
        
        Args:
            address: The address to query
            protocol: The blockchain protocol
            
        Returns:
            Optional[Dict[str, Any]]: Account information or None if not found
        """
        try:
            verifier = self._get_verifier(protocol)
            return await verifier.get_account_info(address)
        except Exception as e:
            self.logger.error(
                f"Account info retrieval error for protocol {protocol.value}: {str(e)}",
                extra={
                    "protocol": protocol.value,
                    "address": address,
                    "error": str(e)
                }
            )
            return None
    
    def get_supported_protocols(self) -> list[BlockchainProtocol]:
        """Get list of supported protocols"""
        return protocol_registry.get_supported_protocols()
    
    def is_protocol_supported(self, protocol: BlockchainProtocol) -> bool:
        """Check if a protocol is supported"""
        return protocol_registry.get_verifier(protocol) is not None
    
    def get_protocol_info(self, protocol: BlockchainProtocol) -> Optional[Dict[str, Any]]:
        """Get information about a specific protocol"""
        try:
            verifier = self._get_verifier(protocol)
            return verifier.get_protocol_info()
        except Exception as e:
            self.logger.error(f"Error getting protocol info for {protocol.value}: {str(e)}")
            return None
