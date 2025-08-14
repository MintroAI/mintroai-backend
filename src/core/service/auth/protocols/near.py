"""
NEAR Protocol implementation for wallet verification and authentication.
This module provides NEAR-specific authentication functionality.
"""

import re
import secrets
import base58
import ed25519
import httpx
import json
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timezone

try:
    from py_near.account import Account
    from py_near.providers import JsonProvider
except ImportError as e:
    raise ImportError(
        "NEAR dependencies not installed. Run: pip install py-near base58 ed25519"
    ) from e

class NEARException(Exception):
    """Custom NEAR exception for error handling"""
    pass

from src.core.service.auth.protocols.base import WalletVerifier, ProtocolConfig, BlockchainProtocol
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class NEARConfig(ProtocolConfig):
    """NEAR-specific configuration"""
    rpc_urls: list[str]
    max_retries: int = 3
    timeout_seconds: int = 30
    
    def __init__(self, **data):
        super().__init__(**data)
        self.protocol = BlockchainProtocol.NEAR


class NEARVerifier(WalletVerifier):
    """NEAR Protocol wallet verifier implementation"""
    
    def __init__(self, config: NEARConfig):
        super().__init__(config)
        self.config: NEARConfig = config
        self.provider: Optional[JsonProvider] = None
        self._connection_established = False
        
        # NEAR account validation patterns
        self.account_patterns = {
            'implicit': re.compile(r'^[0-9a-f]{64}$'),  # 64 hex chars for implicit accounts
            'named': re.compile(r'^[a-z0-9_\-\.]+$'),   # Named accounts
            'subaccount': re.compile(r'^[a-z0-9_\-\.]+\.[a-z0-9_\-\.]+$')  # Sub-accounts
        }
    
    async def initialize(self) -> None:
        """Initialize NEAR provider with proper error handling"""
        try:
            # Use list of RPC URLs for failover (py-near 1.1.57 supports this)
            rpc_urls = self.config.rpc_urls if self.config.rpc_urls else ["https://rpc.testnet.near.org"]
            
            self.logger.info(f"Initializing NEAR provider with RPCs: {rpc_urls}")
            
            # Create JsonProvider with RPC list for automatic failover
            self.provider = JsonProvider(rpc_urls, timeout=10)
            
            # Test connection with a simple RPC call instead of Account.startup()
            # This avoids the "argument of type 'JsonProvider' is not iterable" error
            try:
                status = await self.provider.get_status()
                self.logger.info(f"NEAR RPC connection successful, chain_id: {status.get('chain_id')}")
            except Exception as status_error:
                self.logger.warning(f"NEAR RPC status check failed: {str(status_error)}")
                # Continue with provider initialization even if status fails
                pass
            
            self._connection_established = True
            self.logger.info(
                f"NEAR provider initialized successfully for {self.config.network_id}",
                extra={
                    "protocol": "near",
                    "network_id": self.config.network_id,
                    "rpc_urls": self.config.rpc_urls
                }
            )
            
        except Exception as e:
            self.logger.error(
                f"Failed to initialize NEAR provider: {str(e)}",
                extra={
                    "protocol": "near",
                    "network_id": self.config.network_id,
                    "error": str(e)
                }
            )
            raise
    
    def validate_address(self, address: str) -> Tuple[bool, Optional[str]]:
        """
        Validate NEAR account ID format
        
        NEAR supports:
        - Implicit accounts: 64 hex characters (derived from public key)
        - Named accounts: 2-64 chars, lowercase, numbers, underscore, hyphen, dots
        - Sub-accounts: parent.child format
        """
        try:
            if not address or not isinstance(address, str):
                return False, "Address must be a non-empty string"
            
            address = address.lower().strip()
            
            # Check length constraints
            if len(address) < 2:
                return False, "Account ID too short (minimum 2 characters)"
            
            if len(address) > 64:
                return False, "Account ID too long (maximum 64 characters)"
            
            # Check for implicit account (64 hex chars)
            if self.account_patterns['implicit'].match(address):
                self.logger.debug(f"Validated implicit NEAR account: {address}")
                return True, None
            
            # Check for named account patterns
            if self.account_patterns['named'].match(address):
                # Additional checks for named accounts
                if address.startswith('.') or address.endswith('.'):
                    return False, "Account ID cannot start or end with a dot"
                
                if '..' in address:
                    return False, "Account ID cannot contain consecutive dots"
                
                if address.startswith('-') or address.endswith('-'):
                    return False, "Account ID cannot start or end with a hyphen"
                
                self.logger.debug(f"Validated named NEAR account: {address}")
                return True, None
            
            return False, "Invalid NEAR account ID format"
            
        except Exception as e:
            self.logger.error(f"Error validating NEAR address {address}: {str(e)}")
            return False, f"Validation error: {str(e)}"
    
    async def verify_signature(
        self,
        address: str,
        message: str,
        signature: str,
        public_key: Optional[str] = None,
        **kwargs
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify NEAR signature
        
        Args:
            address: NEAR account ID
            message: Original message that was signed
            signature: Base58-encoded signature
            public_key: Base58-encoded public key (optional, will query if not provided)
        """
        try:
            # Validate address first
            is_valid_address, addr_error = self.validate_address(address)
            if not is_valid_address:
                return False, f"Invalid address: {addr_error}"
            
            # Get public key if not provided
            if not public_key:
                if not self._connection_established:
                    return False, "NEAR provider not initialized - public key required for offline verification"
                public_key = await self._get_account_public_key(address)
                if not public_key:
                    return False, "Could not retrieve public key for account"
            
            # Verify signature using ed25519
            is_valid = self._verify_ed25519_signature(message, signature, public_key)
            
            if is_valid:
                self.logger.info(
                    f"NEAR signature verified successfully for {address}",
                    extra={
                        "protocol": "near",
                        "account_id": address,
                        "network_id": self.config.network_id
                    }
                )
                return True, None
            else:
                self.logger.warning(
                    f"NEAR signature verification failed for {address}",
                    extra={
                        "protocol": "near",
                        "account_id": address,
                        "network_id": self.config.network_id
                    }
                )
                return False, "Invalid signature"
                
        except Exception as e:
            error_msg = f"NEAR signature verification error: {str(e)}"
            self.logger.error(
                error_msg,
                extra={
                    "protocol": "near",
                    "account_id": address,
                    "error": str(e)
                }
            )
            return False, error_msg
    
    def _verify_ed25519_signature(
        self,
        message: str,
        signature: str,
        public_key: str
    ) -> bool:
        """Verify ed25519 signature using NEAR's signing format"""
        try:
            # Decode signature and public key from base58
            signature_bytes = base58.b58decode(signature)
            
            # NEAR public keys are prefixed with "ed25519:"
            if public_key.startswith("ed25519:"):
                public_key = public_key[8:]  # Remove prefix
            
            public_key_bytes = base58.b58decode(public_key)
            
            # Create verifying key
            verifying_key = ed25519.VerifyingKey(public_key_bytes)
            
            # Verify signature
            message_bytes = message.encode('utf-8')
            verifying_key.verify(signature_bytes, message_bytes)
            
            return True
            
        except (ed25519.BadSignatureError, ValueError, Exception) as e:
            self.logger.debug(f"Signature verification failed: {str(e)}")
            return False
    
    async def _get_account_public_key(self, account_id: str) -> Optional[str]:
        """Get the first public key for a NEAR account"""
        try:
            account = Account(account_id, rpc_addr=self.provider)
            await account.startup()
            
            # Get access keys for the account
            access_keys = await account.get_access_keys()
            
            if access_keys and len(access_keys) > 0:
                # Return the first full access key
                for key_info in access_keys:
                    if key_info.get('access_key', {}).get('permission') == 'FullAccess':
                        return key_info.get('public_key')
                
                # If no full access key, return the first key
                return access_keys[0].get('public_key')
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting public key for {account_id}: {str(e)}")
            return None
    
    def create_challenge_message(self, nonce: str, account_id: str = None, **kwargs) -> str:
        """Create NEAR-specific challenge message"""
        timestamp = datetime.now(timezone.utc).isoformat()
        
        message_parts = [
            "Sign in to MintroAI",
            f"Network: {self.config.network_id}",
            f"Nonce: {nonce}",
            f"Timestamp: {timestamp}"
        ]
        
        if account_id:
            message_parts.insert(1, f"Account: {account_id}")
        
        return "\n".join(message_parts)
    
    async def get_account_info(self, address: str) -> Optional[Dict[str, Any]]:
        """Get NEAR account information using direct HTTP RPC (py-near has bugs)"""
        try:
            # Always use direct HTTP RPC due to py-near Account.startup() bug
            return await self._get_account_info_http(address)
            
        except Exception as e:
            self.logger.error(f"Error getting NEAR account info for {address}: {str(e)}")
            return None
    
    async def _get_account_info_http(self, address: str) -> Optional[Dict[str, Any]]:
        """Get account info using direct HTTP RPC calls (bypass py-near bugs)"""
        try:
            rpc_url = self.config.rpc_urls[0] if self.config.rpc_urls else "https://rpc.testnet.near.org"
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get account state
                account_payload = {
                    "jsonrpc": "2.0",
                    "id": "account-info",
                    "method": "query",
                    "params": {
                        "request_type": "view_account",
                        "finality": "final",
                        "account_id": address
                    }
                }
                
                response = await client.post(rpc_url, json=account_payload)
                response.raise_for_status()
                data = response.json()
                
                if "error" in data:
                    if "does not exist" in data["error"].get("data", "").lower():
                        self.logger.debug(f"NEAR account {address} does not exist")
                        return None
                    raise Exception(f"RPC Error: {data['error']}")
                
                account_data = data.get("result", {})
                
                return {
                    "account_id": address,
                    "balance": account_data.get("amount", "0"),
                    "storage_usage": account_data.get("storage_usage", 0),
                    "code_hash": account_data.get("code_hash"),
                    "network_id": self.config.network_id,
                    "protocol": "near",
                    "account_type": "named" if "." in address else "implicit" if len(address) == 64 else "unknown",
                    "rpc_method": "direct_http"
                }
                
        except httpx.RequestError as e:
            self.logger.error(f"HTTP request failed for account {address}: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Direct HTTP RPC failed for account {address}: {str(e)}")
            return None

    def generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce for NEAR challenges"""
        return "0x" + secrets.token_hex(32)


def create_near_verifier(
    network_id: str = "testnet",
    rpc_urls: Optional[list[str]] = None
) -> NEARVerifier:
    """Factory function to create a NEAR verifier with default configuration"""
    
    if rpc_urls is None:
        if network_id == "testnet":
            rpc_urls = [
                "https://rpc.testnet.near.org",
                "https://test.rpc.fastnear.com"
            ]
        elif network_id == "mainnet":
            rpc_urls = [
                "https://rpc.mainnet.near.org",
                "https://rpc.fastnear.com"
            ]
        else:
            raise ValueError(f"Unknown network_id: {network_id}")
    
    config = NEARConfig(
        protocol=BlockchainProtocol.NEAR,
        network_id=network_id,
        rpc_urls=rpc_urls,
        enabled=True
    )
    
    return NEARVerifier(config)