"""Funding service for Chain Signatures."""

import os
from typing import Dict, Optional
from decimal import Decimal

from web3 import Web3
from eth_account import Account
from eth_utils import is_address

from src.core.logger.logger import logger
from .models import (
    FundingRequest,
    FundingResponse,
    BalanceResponse,
    FundingStatus,
    NetworkBalance
)


class FundingService:
    """Service for funding Chain Signatures derived addresses."""
    
    # Network configurations for Chain Signatures
    NETWORK_CONFIGS = {
        "97": {  # BSC Testnet
            "rpc_url": "https://data-seed-prebsc-1-s1.binance.org:8545",
            "funding_amount": "0.0025",  # in BNB
            "name": "BSC Testnet"
        },
        "1313161555": {  # Aurora Testnet
            "rpc_url": "https://testnet.aurora.dev",
            "funding_amount": "0.0025",  # in ETH
            "name": "Aurora Testnet"
        },
        "42161": {  # Arbitrum
            "rpc_url": "https://arb1.arbitrum.io/rpc",
            "funding_amount": "0.001",  # in ETH
            "name": "Arbitrum"
        }
    }
    
    def __init__(self):
        """Initialize funding service."""
        self.funder_private_key = os.getenv("NEXT_PUBLIC_FUNDER_PRIVATE_KEY")
        self.funder_account = None
        
        if self.funder_private_key:
            try:
                self.funder_account = Account.from_key(self.funder_private_key)
                logger.info(f"Funding service initialized with address: {self.funder_account.address}")
            except Exception as e:
                logger.error(f"Failed to initialize funder account: {e}")
                self.funder_account = None
        else:
            logger.warning("NEXT_PUBLIC_FUNDER_PRIVATE_KEY not configured - funding service disabled")
    
    async def fund_address(self, request: FundingRequest) -> FundingResponse:
        """
        Fund a derived address for Chain Signatures.
        
        Args:
            request: Funding request with address and chain_id
            
        Returns:
            FundingResponse with transaction details
        """
        try:
            # Validate address
            if not is_address(request.address):
                return FundingResponse(
                success=False,
                funded=False,
                message="Invalid Ethereum address format",
                error="Invalid Ethereum address format"
            )
            
            # Convert to checksum address
            checksum_address = Web3.to_checksum_address(request.address)
            
            # Check network configuration
            network_config = self.NETWORK_CONFIGS.get(request.chain_id)
            if not network_config:
                return FundingResponse(
                success=False,
                funded=False,
                message=f"Unsupported chain ID: {request.chain_id}",
                error=f"Unsupported chain ID: {request.chain_id}"
            )
            
            # Check if funder is configured
            if not self.funder_account:
                logger.error("Funding service not configured")
                return FundingResponse(
                    success=False,
                    funded=False,
                    message="Funding service not configured. Please contact administrator.",
                    error="Funding service not configured"
                )
            
            # Connect to network
            w3 = Web3(Web3.HTTPProvider(network_config["rpc_url"]))
            
            # Check if connected
            if not w3.is_connected():
                logger.error(f"Failed to connect to {network_config['name']}")
                return FundingResponse(
                    success=False,
                    funded=False,
                    message="Network connection error. Please try again.",
                    error="Network connection error"
                )
            
            # Check funder balance
            funder_balance = w3.eth.get_balance(self.funder_account.address)
            funding_amount_wei = w3.to_wei(network_config["funding_amount"], "ether")
            
            if funder_balance < funding_amount_wei:
                logger.error(
                    f"Insufficient funder balance. Required: {network_config['funding_amount']}, "
                    f"Available: {w3.from_wei(funder_balance, 'ether')}"
                )
                return FundingResponse(
                    success=False,
                    funded=False,
                    message="Funding failed",
                    error="Insufficient funder balance"
                )
            
            # Check if address already has sufficient balance
            address_balance = w3.eth.get_balance(checksum_address)
            minimum_balance = funding_amount_wei // 2  # Half of funding amount as minimum
            
            if address_balance >= minimum_balance:
                logger.info(
                    f"Address {checksum_address} already has sufficient balance: "
                    f"{w3.from_wei(address_balance, 'ether')} ETH"
                )
                return FundingResponse(
                    success=True,
                    funded=False,
                    amount="0",
                    message="Address already has sufficient balance"
                )
            
            # Build and send transaction
            logger.info(
                f"Funding address {checksum_address} on {network_config['name']} "
                f"with {network_config['funding_amount']} ETH/BNB"
            )
            
            # Get nonce
            nonce = w3.eth.get_transaction_count(self.funder_account.address)
            
            # Build transaction
            transaction = {
                "to": checksum_address,
                "value": funding_amount_wei,
                "gas": 21000,  # Standard gas for ETH transfer
                "gasPrice": w3.eth.gas_price,
                "nonce": nonce,
                "chainId": int(request.chain_id)
            }
            
            # Sign transaction
            signed_txn = self.funder_account.sign_transaction(transaction)
            
            # Send transaction
            tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            logger.info(f"Funding transaction sent: {tx_hash.hex()}")
            
            # Wait for confirmation
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
            
            return FundingResponse(
                success=True,
                funded=True,
                transactionHash=tx_hash.hex(),
                amount=network_config['funding_amount'],
                message="Address funded successfully"
            )
            
        except Exception as e:
            logger.error(f"Funding error: {e}")
            
            # Handle specific error types
            error_message = str(e)
            if "insufficient funds" in error_message.lower():
                return FundingResponse(
                    success=False,
                    funded=False,
                    message="Funding failed",
                    error="Insufficient funder balance"
                )
            
            return FundingResponse(
                success=False,
                funded=False,
                message="Funding failed",
                error=error_message
            )
    
    async def check_balance(self, address: str, chain_id: str) -> BalanceResponse:
        """
        Check address balance on specified chain.
        
        Args:
            address: Address to check
            chain_id: Chain ID
            
        Returns:
            BalanceResponse with balance information
        """
        try:
            # Validate address
            if not is_address(address):
                raise ValueError("Invalid Ethereum address")
            
            # Convert to checksum address
            checksum_address = Web3.to_checksum_address(address)
            
            # Check network configuration
            network_config = self.NETWORK_CONFIGS.get(chain_id)
            if not network_config:
                raise ValueError(f"Unsupported chain ID: {chain_id}")
            
            # Connect to network
            w3 = Web3(Web3.HTTPProvider(network_config["rpc_url"]))
            
            # Check if connected
            if not w3.is_connected():
                raise ConnectionError(f"Failed to connect to {network_config['name']}")
            
            # Get balance
            balance_wei = w3.eth.get_balance(checksum_address)
            balance_eth = str(w3.from_wei(balance_wei, "ether"))
            
            return BalanceResponse(
                success=True,
                address=checksum_address,
                chain_id=chain_id,
                balance=balance_eth,
                network=network_config["name"]
            )
            
        except Exception as e:
            logger.error(f"Balance check error: {e}")
            raise
    
    async def get_funding_status(self) -> FundingStatus:
        """
        Get funding service status and statistics.
        
        Returns:
            FundingStatus with service information
        """
        try:
            # Check if configured
            if not self.funder_account:
                return FundingStatus(
                    configured=False,
                    message="Funding service not configured"
                )
            
            funder_address = self.funder_account.address
            balances = {}
            
            # Check balance on all networks
            for chain_id, config in self.NETWORK_CONFIGS.items():
                try:
                    w3 = Web3(Web3.HTTPProvider(config["rpc_url"]))
                    
                    if w3.is_connected():
                        balance_wei = w3.eth.get_balance(funder_address)
                        balance_eth = str(w3.from_wei(balance_wei, "ether"))
                        funding_amount_wei = w3.to_wei(config["funding_amount"], "ether")
                        
                        balances[chain_id] = NetworkBalance(
                            network=config["name"],
                            balance=balance_eth,
                            funding_amount=config["funding_amount"],
                            can_fund=balance_wei >= funding_amount_wei
                        )
                    else:
                        balances[chain_id] = NetworkBalance(
                            network=config["name"],
                            funding_amount=config["funding_amount"],
                            error="Failed to connect to network"
                        )
                except Exception as e:
                    logger.error(f"Error checking balance for chain {chain_id}: {e}")
                    balances[chain_id] = NetworkBalance(
                        network=config["name"],
                        funding_amount=config["funding_amount"],
                        error="Failed to check balance"
                    )
            
            return FundingStatus(
                configured=True,
                funder_address=funder_address,
                balances=balances
            )
            
        except Exception as e:
            logger.error(f"Status check error: {e}")
            raise
