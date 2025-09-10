"""
Cryptographic utilities for authentication services.
This module provides common cryptographic functions used across different protocols.
"""

import secrets
import base58
import ed25519
import hashlib
import base64
from typing import Tuple, Optional, Dict, Any

try:
    from borsh_construct import CStruct, U32, String, Option, Bytes
except ImportError as e:
    raise ImportError(
        "NEAR borsh dependencies not installed. Run: pip install borsh-construct"
    ) from e

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


def generate_secure_nonce(length: int = 32) -> str:
    """
    Generate a cryptographically secure nonce
    
    Args:
        length: Length of the nonce in bytes (default: 32 bytes = 256 bits)
        
    Returns:
        str: Hex-encoded nonce with '0x' prefix
    """
    return "0x" + secrets.token_hex(length)


def generate_ed25519_keypair() -> Tuple[str, str]:
    """
    Generate a new ed25519 key pair for testing
    
    Returns:
        Tuple[str, str]: (private_key_base58, public_key_base58)
    """
    try:
        # Generate private key
        private_key_bytes = secrets.token_bytes(32)
        private_key = ed25519.SigningKey(private_key_bytes)
        public_key = private_key.get_verifying_key()
        
        # Encode keys as base58
        private_key_b58 = base58.b58encode(private_key_bytes).decode('utf-8')
        public_key_b58 = base58.b58encode(public_key.to_bytes()).decode('utf-8')
        
        return private_key_b58, public_key_b58
        
    except Exception as e:
        logger.error(f"Failed to generate ed25519 keypair: {str(e)}")
        raise


def sign_message_ed25519(message: str, private_key_b58: str) -> str:
    """
    Sign a message using ed25519 private key
    
    Args:
        message: Message to sign
        private_key_b58: Base58-encoded private key
        
    Returns:
        str: Base58-encoded signature
    """
    try:
        # Decode private key
        private_key_bytes = base58.b58decode(private_key_b58)
        signing_key = ed25519.SigningKey(private_key_bytes)
        
        # Sign message
        message_bytes = message.encode('utf-8')
        signature = signing_key.sign(message_bytes)
        
        # Return base58-encoded signature
        return base58.b58encode(signature).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Failed to sign message: {str(e)}")
        raise


def verify_ed25519_signature(
    message: str,
    signature_b58: str,
    public_key_b58: str
) -> bool:
    """
    Verify an ed25519 signature
    
    Args:
        message: Original message
        signature_b58: Base58-encoded signature
        public_key_b58: Base58-encoded public key
        
    Returns:
        bool: True if signature is valid
    """
    try:
        # Decode signature and public key
        signature_bytes = base58.b58decode(signature_b58)
        public_key_bytes = base58.b58decode(public_key_b58)
        
        # Create verifying key
        verifying_key = ed25519.VerifyingKey(public_key_bytes)
        
        # Verify signature
        message_bytes = message.encode('utf-8')
        verifying_key.verify(signature_bytes, message_bytes)
        
        return True
        
    except (ed25519.BadSignatureError, ValueError, Exception):
        return False


def format_near_public_key(public_key_b58: str) -> str:
    """
    Format public key for NEAR protocol (add ed25519: prefix)
    
    Args:
        public_key_b58: Base58-encoded public key
        
    Returns:
        str: NEAR-formatted public key
    """
    if not public_key_b58.startswith("ed25519:"):
        return f"ed25519:{public_key_b58}"
    return public_key_b58


def parse_near_public_key(near_public_key: str) -> str:
    """
    Parse NEAR public key to get base58-encoded key
    
    Args:
        near_public_key: NEAR-formatted public key (with ed25519: prefix)
        
    Returns:
        str: Base58-encoded public key without prefix
    """
    if near_public_key.startswith("ed25519:"):
        return near_public_key[8:]  # Remove "ed25519:" prefix
    return near_public_key


# NEAR signMessage Standard Implementation
def create_near_sign_message_payload(
    message: str,
    nonce: str,
    recipient: str,
    callback_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create NEAR signMessage payload according to NEAR standard
    
    Args:
        message: The message to sign
        nonce: 32-byte hex nonce (with or without 0x prefix)
        recipient: App domain/recipient
        callback_url: Optional callback URL
        
    Returns:
        Dict containing the payload structure
    """
    # Remove 0x prefix if present and convert to bytes
    nonce_clean = nonce[2:] if nonce.startswith('0x') else nonce
    nonce_bytes = bytes.fromhex(nonce_clean)
    
    if len(nonce_bytes) != 32:
        raise ValueError(f"Nonce must be exactly 32 bytes, got {len(nonce_bytes)}")
    
    return {
        "tag": 2147484061,  # Fixed tag for NEAR signMessage
        "message": message,
        "nonce": nonce_bytes,
        "recipient": recipient,
        "callbackUrl": callback_url
    }


def serialize_near_payload(payload: Dict[str, Any]) -> bytes:
    """
    Serialize NEAR signMessage payload using borsh
    
    Args:
        payload: NEAR signMessage payload
        
    Returns:
        bytes: Borsh-serialized payload
    """
    try:
        # Define the borsh schema for NEAR signMessage
        from construct import Bytes as ConstructBytes
        
        schema = CStruct(
            "tag" / U32,
            "message" / String,
            "nonce" / ConstructBytes(32),  # Fixed 32 bytes
            "recipient" / String,
            "callbackUrl" / Option(String)
        )
        
        # Serialize the payload
        return schema.build(payload)
        
    except Exception as e:
        logger.error(f"Failed to serialize NEAR payload: {str(e)}")
        raise ValueError(f"Borsh serialization failed: {str(e)}")


def create_near_message_hash(
    message: str,
    nonce: str,
    recipient: str,
    callback_url: Optional[str] = None
) -> bytes:
    """
    Create the message hash that NEAR wallets actually sign
    
    Args:
        message: The message to sign
        nonce: 32-byte hex nonce
        recipient: App domain/recipient
        callback_url: Optional callback URL
        
    Returns:
        bytes: SHA256 hash of the borsh-serialized payload
    """
    try:
        # Create payload
        payload = create_near_sign_message_payload(message, nonce, recipient, callback_url)
        
        # Serialize with borsh
        serialized = serialize_near_payload(payload)
        
        # Hash with SHA256
        return hashlib.sha256(serialized).digest()
        
    except Exception as e:
        logger.error(f"Failed to create NEAR message hash: {str(e)}")
        raise


def verify_near_sign_message(
    signature_data: Dict[str, Any],
    message: str,
    nonce: str,
    recipient: str,
    callback_url: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """
    Verify NEAR signMessage signature according to NEAR standard
    
    Args:
        signature_data: Dict containing accountId, publicKey, signature
        message: Original message
        nonce: 32-byte hex nonce
        recipient: App domain/recipient
        callback_url: Optional callback URL
        
    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)
    """
    try:
        # Extract signature components
        account_id = signature_data.get("accountId")
        public_key = signature_data.get("publicKey")
        signature = signature_data.get("signature")
        
        if not all([account_id, public_key, signature]):
            return False, "Missing required signature components (accountId, publicKey, signature)"
        
        # Create the message hash that was actually signed
        message_hash = create_near_message_hash(message, nonce, recipient, callback_url)
        
        # Decode signature from base64
        try:
            signature_bytes = base64.b64decode(signature)
        except Exception as e:
            return False, f"Invalid base64 signature: {str(e)}"
        
        # Parse public key
        public_key_clean = parse_near_public_key(public_key)
        
        try:
            public_key_bytes = base58.b58decode(public_key_clean)
        except Exception as e:
            return False, f"Invalid base58 public key: {str(e)}"
        
        # Verify signature using ed25519
        try:
            verifying_key = ed25519.VerifyingKey(public_key_bytes)
            verifying_key.verify(signature_bytes, message_hash)
            
            logger.info(f"NEAR signMessage signature verified successfully for {account_id}")
            return True, None
            
        except ed25519.BadSignatureError:
            return False, "Invalid signature"
        except Exception as e:
            return False, f"Signature verification error: {str(e)}"
            
    except Exception as e:
        error_msg = f"NEAR signMessage verification failed: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def sign_message_near_standard(
    message: str,
    nonce: str,
    recipient: str,
    private_key_b58: str,
    account_id: str,
    callback_url: Optional[str] = None
) -> Dict[str, str]:
    """
    Sign a message using NEAR signMessage standard (for testing)
    
    Args:
        message: Message to sign
        nonce: 32-byte hex nonce
        recipient: App domain/recipient
        private_key_b58: Base58-encoded private key
        account_id: NEAR account ID
        callback_url: Optional callback URL
        
    Returns:
        Dict containing accountId, publicKey, signature
    """
    try:
        # Create message hash
        message_hash = create_near_message_hash(message, nonce, recipient, callback_url)
        
        # Decode private key
        private_key_bytes = base58.b58decode(private_key_b58)
        signing_key = ed25519.SigningKey(private_key_bytes)
        
        # Get public key
        public_key = signing_key.get_verifying_key()
        public_key_b58 = base58.b58encode(public_key.to_bytes()).decode('utf-8')
        
        # Sign the hash
        signature_bytes = signing_key.sign(message_hash)
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        
        return {
            "accountId": account_id,
            "publicKey": f"ed25519:{public_key_b58}",
            "signature": signature_b64
        }
        
    except Exception as e:
        logger.error(f"Failed to sign message with NEAR standard: {str(e)}")
        raise