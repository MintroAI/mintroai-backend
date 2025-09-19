"""Integration tests for funding endpoints."""

import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from web3 import Web3

from src.app import create_app


@pytest.mark.asyncio
class TestFundingEndpoints:
    """Test funding API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        app = create_app()
        return TestClient(app)
    
    @pytest.fixture
    def mock_funding_service(self):
        """Create mock funding service."""
        mock = AsyncMock()
        return mock
    
    def test_fund_address_endpoint_success(self, client):
        """Test successful funding endpoint."""
        with patch("src.api.controller.funding.funding_controller.FundingService") as MockService:
            # Setup mock
            mock_service = MockService.return_value
            mock_response = AsyncMock(return_value={
                "success": True,
                "message": "Successfully funded",
                "tx_hash": "0x" + "a" * 64,
                "block_number": 12345,
                "funded": True,
                "balance": None
            })
            mock_service.fund_address = mock_response
            
            # Make request
            response = client.post(
                "/api/fund-address",
                json={
                    "address": "0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
                    "chain_id": "97"
                }
            )
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["funded"] is True
            assert data["tx_hash"] is not None
    
    def test_fund_address_endpoint_missing_params(self, client):
        """Test funding endpoint with missing parameters."""
        # Make request without chain_id
        response = client.post(
            "/api/fund-address",
            json={
                "address": "0x742D35CC6634c0532925A3b844BC9E7595F0BEb0"
            }
        )
        
        # Assert
        assert response.status_code == 422  # Validation error
    
    def test_check_balance_endpoint_success(self, client):
        """Test successful balance check endpoint."""
        with patch("src.api.controller.funding.funding_controller.FundingService") as MockService:
            # Setup mock
            mock_service = MockService.return_value
            mock_response = AsyncMock(return_value={
                "success": True,
                "address": "0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
                "chain_id": "97",
                "balance": "0.5",
                "network": "BSC Testnet"
            })
            mock_service.check_balance = mock_response
            
            # Make request
            response = client.get(
                "/api/check-balance",
                params={
                    "address": "0x742D35CC6634c0532925A3b844BC9E7595F0BEb0",
                    "chainId": "97"
                }
            )
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["balance"] == "0.5"
            assert data["network"] == "BSC Testnet"
    
    def test_check_balance_endpoint_missing_params(self, client):
        """Test balance check endpoint with missing parameters."""
        # Make request without chainId
        response = client.get(
            "/api/check-balance",
            params={
                "address": "0x742D35CC6634c0532925A3b844BC9E7595F0BEb0"
            }
        )
        
        # Assert
        assert response.status_code == 400
        assert "Missing required parameters" in response.json()["detail"]
    
    def test_funding_status_endpoint_configured(self, client):
        """Test funding status endpoint when configured."""
        with patch("src.api.controller.funding.funding_controller.FundingService") as MockService:
            # Setup mock
            mock_service = MockService.return_value
            mock_response = AsyncMock(return_value={
                "configured": True,
                "funder_address": "0x" + "b" * 40,
                "balances": {
                    "97": {
                        "network": "BSC Testnet",
                        "balance": "1.0",
                        "funding_amount": "0.0025",
                        "can_fund": True
                    }
                }
            })
            mock_service.get_funding_status = mock_response
            
            # Make request
            response = client.get("/api/funding-status")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["configured"] is True
            assert data["funder_address"] is not None
            assert "97" in data["balances"]
    
    def test_funding_status_endpoint_not_configured(self, client):
        """Test funding status endpoint when not configured."""
        with patch("src.api.controller.funding.funding_controller.FundingService") as MockService:
            # Setup mock
            mock_service = MockService.return_value
            mock_response = AsyncMock(return_value={
                "configured": False,
                "message": "Funding service not configured"
            })
            mock_service.get_funding_status = mock_response
            
            # Make request
            response = client.get("/api/funding-status")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["configured"] is False
            assert data["message"] == "Funding service not configured"
