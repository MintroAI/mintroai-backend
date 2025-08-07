"""
Cryptographic utilities for authentication services.
This module provides common cryptographic functions used across different protocols.
"""

import secrets
import base58
import ed25519
from typing import Tuple, Optional

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