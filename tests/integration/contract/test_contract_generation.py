"""Integration tests for contract generation endpoint"""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

from src.core.service.auth.models.token import TokenPayload


@pytest.mark.asyncio
class TestContractGeneration:
    """Test contract generation endpoint"""
    
    async def test_generate_token_contract_success(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test successful token contract generation"""
        
        # Prepare request data
        contract_data = {
            "contractType": "token",
            "tokenName": "TestToken",
            "tokenSymbol": "TST",
            "decimals": 18,
            "initialSupply": "1000000",
            "mintable": True,
            "burnable": True,
            "isChainSignatures": False
        }
        
        # Mock JWT verification
        mock_payload = TokenPayload(
            wallet_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            wallet_type="evm",
            protocol="evm",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            # Make request
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Assert response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "contractCode" in data
            assert "Mock" in data["contractCode"]  # Since CONTRACT_GENERATOR_URL is not set
    
    async def test_generate_vesting_contract_success(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test successful vesting contract generation"""
        
        # Prepare request data
        contract_data = {
            "contractType": "vesting",
            "tokenAddress": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            "tgeTimestamp": 1735689600,
            "tgeRate": 10,
            "cliff": 30,
            "releaseRate": 10,
            "period": 30,
            "vestingSupply": 1000000,
            "users": ["0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"],
            "amts": [1000000]
        }
        
        # Mock JWT verification
        mock_payload = TokenPayload(
            wallet_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            wallet_type="evm",
            protocol="evm",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            # Make request
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Assert response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "contractCode" in data
            assert "Vesting" in data["contractCode"]
    
    async def test_generate_contract_without_auth(self, async_client: AsyncClient):
        """Test contract generation without authentication"""
        
        contract_data = {
            "contractType": "token",
            "tokenName": "TestToken"
        }
        
        # Make request without auth header
        response = await async_client.post(
            "/api/v1/generate-contract",
            json=contract_data
        )
        
        # Should return 403 (HTTPBearer requirement)
        assert response.status_code == 403
        assert "Not authenticated" in response.json()["detail"]
    
    async def test_generate_contract_invalid_token(self, async_client: AsyncClient):
        """Test contract generation with invalid token"""
        
        contract_data = {
            "contractType": "token",
            "tokenName": "TestToken"
        }
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.side_effect = Exception("Invalid token")
            
            # Make request with invalid token
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": "Bearer invalid_token"}
            )
            
            # Should return 401
            assert response.status_code == 401
            assert "Authentication required" in response.json()["detail"]
    
    async def test_generate_contract_minimal_fields(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test contract generation with minimal fields (only contractType)"""
        
        contract_data = {
            "contractType": "token"
        }
        
        # Mock JWT verification
        mock_payload = TokenPayload(
            wallet_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            wallet_type="evm",
            protocol="evm",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            # Make request
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Assert response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "contractCode" in data
    
    async def test_generate_contract_invalid_type(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test contract generation with invalid contract type"""
        
        contract_data = {
            "contractType": "invalid_type"
        }
        
        # Mock JWT verification
        mock_payload = TokenPayload(
            wallet_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            wallet_type="evm",
            protocol="evm",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            # Make request
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Should return 422 (validation error)
            assert response.status_code == 422
    
    async def test_generate_contract_with_chain_signatures(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test contract generation with NEAR chain signatures flag"""
        
        contract_data = {
            "contractType": "token",
            "tokenName": "NearToken",
            "isChainSignatures": True  # NEAR wallet
        }
        
        # Mock JWT verification with NEAR wallet
        mock_payload = TokenPayload(
            wallet_address="mintro.near",
            wallet_type="near",
            protocol="near",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            # Make request
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Assert response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "contractCode" in data
    
    async def test_generate_contract_validation_errors(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test contract generation with validation errors"""
        
        # Test invalid decimals
        contract_data = {
            "contractType": "token",
            "decimals": 25  # Max is 18
        }
        
        mock_payload = TokenPayload(
            wallet_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            wallet_type="evm",
            protocol="evm",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Should return 422 (validation error)
            assert response.status_code == 422
            
        # Test invalid transfer tax
        contract_data = {
            "contractType": "token",
            "transferTax": 150  # Max is 100
        }
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Should return 422 (validation error)
            assert response.status_code == 422
    
    async def test_generate_vesting_contract_mismatched_arrays(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test vesting contract with mismatched users and amounts arrays"""
        
        contract_data = {
            "contractType": "vesting",
            "users": ["0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2"],
            "amts": [1000000]  # Only one amount for two users
        }
        
        mock_payload = TokenPayload(
            wallet_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            wallet_type="evm",
            protocol="evm",
            challenge_id="test_challenge",
            session_id="test_session"
        )
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = mock_payload
            
            response = await async_client.post(
                "/api/v1/generate-contract",
                json=contract_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Should return 422 (validation error)
            assert response.status_code == 422
