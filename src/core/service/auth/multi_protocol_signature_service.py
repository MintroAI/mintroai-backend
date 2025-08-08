"""
Multi-Protocol Signature Verification Service.
This service provides a unified interface for verifying signatures across different blockchain protocols.
"""

from typing import Tuple, Optional

from src.core.service.auth.protocols.base import protocol_registry, BlockchainProtocol
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class MultiProtocolSignatureService:
    """Service for verifying wallet signatures across multiple blockchain protocols"""
    
    def __init__(self):
        self.registry = protocol_registry
    
    async def verify_signature(
        self,
        protocol: BlockchainProtocol,
        address: str,
        message: str,
        signature: str,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a signature for the specified protocol
        
        Args:
            protocol: The blockchain protocol (evm, near, etc.)
            address: The address/account ID that claims to have signed
            message: The original message that was signed
            signature: The signature to verify
            **kwargs: Protocol-specific additional parameters (e.g., public_key for NEAR)
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            # Get the appropriate verifier for the protocol
            verifier = self.registry.get_verifier(protocol)
            if not verifier:
                error_msg = f"Protocol '{protocol}' is not supported or not registered"
                logger.error(
                    error_msg,
                    extra={
                        "protocol": protocol,
                        "address": address,
                        "supported_protocols": [p.value for p in self.registry.get_supported_protocols()]
                    }
                )
                return False, error_msg
            
            # Verify signature using the protocol-specific verifier
            is_valid, error = await verifier.verify_signature(
                address=address,
                message=message,
                signature=signature,
                **kwargs
            )
            
            if is_valid:
                logger.info(
                    "Multi-protocol signature verified successfully",
                    extra={
                        "protocol": protocol.value,
                        "address": address
                    }
                )
            else:
                logger.warning(
                    "Multi-protocol signature verification failed",
                    extra={
                        "protocol": protocol.value,
                        "address": address,
                        "error": error
                    }
                )
            
            return is_valid, error
            
        except Exception as e:
            error_msg = f"Signature verification failed: {str(e)}"
            logger.error(
                error_msg,
                extra={
                    "protocol": protocol.value,
                    "address": address,
                    "error": str(e)
                }
            )
            return False, error_msg
    
    def validate_address(self, protocol: BlockchainProtocol, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate an address for the specified protocol
        
        Args:
            protocol: The blockchain protocol
            address: The address to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            verifier = self.registry.get_verifier(protocol)
            if not verifier:
                error_msg = f"Protocol '{protocol}' is not supported"
                logger.error(error_msg, extra={"protocol": protocol, "address": address})
                return False, error_msg
            
            return verifier.validate_address(address)
            
        except Exception as e:
            error_msg = f"Address validation failed: {str(e)}"
            logger.error(
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
        protocol: BlockchainProtocol,
        nonce: str,
        **kwargs
    ) -> Optional[str]:
        """
        Create a protocol-specific challenge message
        
        Args:
            protocol: The blockchain protocol
            nonce: Unique nonce for the challenge
            **kwargs: Protocol-specific parameters
            
        Returns:
            Optional[str]: Challenge message or None if protocol not supported
        """
        try:
            verifier = self.registry.get_verifier(protocol)
            if not verifier:
                logger.error(
                    f"Protocol '{protocol}' is not supported",
                    extra={"protocol": protocol}
                )
                return None
            
            message = verifier.create_challenge_message(nonce, **kwargs)
            logger.debug(
                "Created challenge message",
                extra={
                    "protocol": protocol.value,
                    "nonce": nonce
                }
            )
            return message
            
        except Exception as e:
            logger.error(
                f"Failed to create challenge message: {str(e)}",
                extra={
                    "protocol": protocol.value,
                    "nonce": nonce,
                    "error": str(e)
                }
            )
            return None
    
    def get_supported_protocols(self) -> list[BlockchainProtocol]:
        """Get list of supported protocols"""
        return self.registry.get_supported_protocols()
    
    def is_protocol_supported(self, protocol: BlockchainProtocol) -> bool:
        """Check if a protocol is supported"""
        return protocol in self.get_supported_protocols()


# Backward compatibility: create an instance that mimics the old SignatureVerificationService
class SignatureVerificationService:
    """
    Backward compatibility wrapper for the old SignatureVerificationService.
    Defaults to EVM protocol for existing code.
    """
    
    def __init__(self):
        self.multi_service = MultiProtocolSignatureService()
        self.default_protocol = BlockchainProtocol.EVM
    
    def verify_signature(self, claimed_address: str, signature: str, message: str) -> Tuple[bool, Optional[str]]:
        """
        Verify signature using EVM protocol (backward compatibility)
        
        Args:
            claimed_address: The address that claims to have signed
            signature: The signature to verify
            message: The original message that was signed
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Import here to avoid circular imports
        import asyncio
        
        # Run the async verification in sync context
        loop = None
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        if loop.is_running():
            # If we're already in an async context, we need to use run_until_complete
            # This is a workaround for backward compatibility
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run,
                    self.multi_service.verify_signature(
                        protocol=self.default_protocol,
                        address=claimed_address,
                        message=message,
                        signature=signature
                    )
                )
                return future.result()
        else:
            return loop.run_until_complete(
                self.multi_service.verify_signature(
                    protocol=self.default_protocol,
                    address=claimed_address,
                    message=message,
                    signature=signature
                )
            )