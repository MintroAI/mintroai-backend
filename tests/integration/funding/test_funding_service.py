"""Integration tests for funding service."""

import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from web3 import Web3

from src.core.service.funding.funding_service import FundingService
from src.core.service.funding.models import FundingRequest


@pytest.mark.asyncio
class TestFundingService:
    """Test funding service functionality."""
    
    @pytest.fixture
    def funding_service(self):
        """Create funding service instance."""
        with patch.dict(os.environ, {"NEXT_PUBLIC_FUNDER_PRIVATE_KEY": "0x" + "1" * 64}):
            service = FundingService()
            return service
    
    @pytest.fixture
    def mock_web3(self):
        """Create mock Web3 instance."""
        mock = MagicMock()
        mock.is_connected.return_value = True
        mock.eth = MagicMock()
        mock.eth.gas_price = 20000000000  # 20 gwei
        mock.to_wei = Web3.to_wei
        mock.from_wei = Web3.from_wei
        return mock
    
    async def test_fund_address_success(self, funding_service, mock_web3):
        """Test successful address funding."""
        # Setup
        request = FundingRequest(
            address="0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
            chain_id="97"
        )
        
        with patch("src.core.service.funding.funding_service.Web3") as MockWeb3:
            MockWeb3.return_value = mock_web3
            MockWeb3.HTTPProvider = MagicMock()
            
            # Mock balances
            mock_web3.eth.get_balance.side_effect = [
                Web3.to_wei("1", "ether"),  # Funder balance
                Web3.to_wei("0", "ether")   # Target address balance
            ]
            
            # Mock transaction
            mock_web3.eth.get_transaction_count.return_value = 0
            mock_web3.eth.send_raw_transaction.return_value = b"0x" + b"a" * 64
            mock_web3.eth.wait_for_transaction_receipt.return_value = {
                "blockNumber": 12345,
                "status": 1
            }
            
            # Execute
            response = await funding_service.fund_address(request)
            
            # Assert
            assert response.success is True
            assert response.funded is True
            assert response.tx_hash is not None
            assert response.block_number == 12345
    
    async def test_fund_address_already_funded(self, funding_service, mock_web3):
        """Test funding when address already has sufficient balance."""
        # Setup
        request = FundingRequest(
            address="0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
            chain_id="97"
        )
        
        with patch("src.core.service.funding.funding_service.Web3") as MockWeb3:
            MockWeb3.return_value = mock_web3
            MockWeb3.HTTPProvider = MagicMock()
            
            # Mock balances - target already has enough
            mock_web3.eth.get_balance.side_effect = [
                Web3.to_wei("1", "ether"),     # Funder balance
                Web3.to_wei("0.002", "ether")  # Target address balance (enough)
            ]
            
            # Execute
            response = await funding_service.fund_address(request)
            
            # Assert
            assert response.success is True
            assert response.funded is False
            assert "already has sufficient balance" in response.message
    
    async def test_fund_address_invalid_address(self, funding_service):
        """Test funding with invalid address."""
        # Setup
        request = FundingRequest(
            address="invalid_address",
            chain_id="97"
        )
        
        # Execute
        response = await funding_service.fund_address(request)
        
        # Assert
        assert response.success is False
        assert "Invalid Ethereum address" in response.message
        assert response.funded is False
    
    async def test_fund_address_unsupported_chain(self, funding_service):
        """Test funding with unsupported chain."""
        # Setup
        request = FundingRequest(
            address="0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
            chain_id="999"
        )
        
        # Execute
        response = await funding_service.fund_address(request)
        
        # Assert
        assert response.success is False
        assert "Unsupported chain ID" in response.message or "Invalid Ethereum address" in response.message
        assert response.funded is False
    
    async def test_fund_address_insufficient_funder_balance(self, funding_service, mock_web3):
        """Test funding when funder has insufficient balance."""
        # Setup
        request = FundingRequest(
            address="0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
            chain_id="97"
        )
        
        with patch("src.core.service.funding.funding_service.Web3") as MockWeb3:
            MockWeb3.return_value = mock_web3
            MockWeb3.HTTPProvider = MagicMock()
            
            # Mock balances - funder doesn't have enough
            mock_web3.eth.get_balance.return_value = Web3.to_wei("0.001", "ether")
            
            # Execute
            response = await funding_service.fund_address(request)
            
            # Assert
            assert response.success is False
            assert "Insufficient balance" in response.message
            assert response.funded is False
    
    async def test_check_balance_success(self, funding_service, mock_web3):
        """Test successful balance check."""
        with patch("src.core.service.funding.funding_service.Web3") as MockWeb3:
            MockWeb3.return_value = mock_web3
            MockWeb3.HTTPProvider = MagicMock()
            
            # Mock balance
            mock_web3.eth.get_balance.return_value = Web3.to_wei("0.5", "ether")
            
            # Execute
            response = await funding_service.check_balance(
                "0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
                "97"
            )
            
            # Assert
            assert response.success is True
            assert response.balance == "0.5"
            assert response.network == "BSC Testnet"
    
    async def test_get_funding_status_configured(self, funding_service, mock_web3):
        """Test funding status when configured."""
        with patch("src.core.service.funding.funding_service.Web3") as MockWeb3:
            MockWeb3.return_value = mock_web3
            MockWeb3.HTTPProvider = MagicMock()
            
            # Mock balances for both networks
            mock_web3.eth.get_balance.side_effect = [
                Web3.to_wei("1", "ether"),    # BSC balance
                Web3.to_wei("0.5", "ether")   # Aurora balance
            ]
            
            # Execute
            status = await funding_service.get_funding_status()
            
            # Assert
            assert status.configured is True
            assert status.funder_address is not None
            assert "97" in status.balances
            assert "1313161555" in status.balances
            assert status.balances["97"].can_fund is True
            assert status.balances["1313161555"].can_fund is True
    
    async def test_get_funding_status_not_configured(self):
        """Test funding status when not configured."""
        # Create service without private key
        with patch.dict(os.environ, {}, clear=True):
            service = FundingService()
            
            # Execute
            status = await service.get_funding_status()
            
            # Assert
            assert status.configured is False
            assert status.message == "Funding service not configured"
            assert status.funder_address is None
