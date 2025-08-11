import binascii
from eth_account.messages import encode_defunct
from eth_account import Account
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from typing import Optional, Tuple
from web3 import Web3

from src.core.logger.logger import logger


class SignatureVerificationService:
    """Service for verifying Ethereum wallet signatures"""

    @staticmethod
    def _to_checksum_address(address: str) -> ChecksumAddress:
        """Convert address to checksum format"""
        try:
            return Web3.to_checksum_address(address.lower())
        except ValueError as e:
            logger.error(str(e), extra={"address": address})
            raise ValueError("Invalid Ethereum address format") from e

    @staticmethod
    def _create_message(message: str) -> bytes:
        """Create a signable message"""
        return encode_defunct(text=message)

    def verify_signature(self, claimed_address: str, signature: str, message: str) -> Tuple[bool, Optional[str]]:
        """
        Verify an Ethereum signature
        
        Args:
            message: The original message that was signed
            signature: The signature to verify
            claimed_address: The address that claims to have signed the message
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            # Convert address to checksum format
            try:
                checksum_address = self._to_checksum_address(claimed_address)
            except ValueError as e:
                error_msg = "Invalid Ethereum address format"
                logger.error(
                    error_msg,
                    extra={
                        "wallet_address": claimed_address,
                        "error": str(e)
                    }
                )
                return False, error_msg
            
            # Convert signature to bytes if it's a hex string
            try:
                if isinstance(signature, str) and signature.startswith("0x"):
                    signature = HexBytes(signature)
                elif isinstance(signature, str):
                    signature = HexBytes("0x" + signature)
                else:
                    signature = HexBytes(signature)
            except (ValueError, binascii.Error) as e:
                error_msg = "Invalid signature format"
                logger.error(
                    error_msg,
                    extra={
                        "wallet_address": claimed_address,
                        "error": str(e)
                    }
                )
                return False, error_msg
            
            # Create signable message
            signable_message = self._create_message(message)
            
            # Recover the address from the signature
            try:
                recovered_address = Account.recover_message(signable_message, signature=signature)
            except (ValueError, binascii.Error) as e:
                error_msg = "Invalid signature format"
                logger.error(
                    error_msg,
                    extra={
                        "wallet_address": claimed_address,
                        "error": str(e)
                    }
                )
                return False, error_msg
            
            # Compare addresses
            is_valid = recovered_address.lower() == checksum_address.lower()
            
            if not is_valid:
                error_msg = "Recovered address does not match claimed address"
                logger.warning(
                    error_msg,
                    extra={
                        "wallet_address": claimed_address,
                        "recovered_address": recovered_address
                    }
                )
                return False, error_msg
            
            logger.info(
                "Signature verified successfully",
                extra={"wallet_address": claimed_address}
            )
            return True, None
            
        except Exception as e:
            error_msg = "Invalid signature format"
            logger.error(
                error_msg,
                extra={
                    "wallet_address": claimed_address,
                    "error": str(e)
                }
            )
            return False, error_msg
