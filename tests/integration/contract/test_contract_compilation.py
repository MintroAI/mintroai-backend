"""Integration tests for contract compilation endpoint"""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

from src.core.service.auth.models.token import TokenPayload


@pytest.mark.asyncio
class TestContractCompilation:
    """Test contract compilation endpoint"""
    
    async def test_compile_contract_success(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test successful contract compilation"""
        
        # Prepare request data
        compile_data = {
            "chatId": "test-chat-id-123"
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
                "/api/v1/compile-contract",
                json=compile_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Assert response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "bytecode" in data
            assert "abi" in data
            assert data["bytecode"].startswith("0x")
    
    async def test_compile_contract_without_auth(self, async_client: AsyncClient):
        """Test contract compilation without authentication"""
        
        compile_data = {
            "chatId": "test-chat-id-123"
        }
        
        # Make request without auth header
        response = await async_client.post(
            "/api/v1/compile-contract",
            json=compile_data
        )
        
        # Should return 403 (HTTPBearer requirement)
        assert response.status_code == 403
        assert "Not authenticated" in response.json()["detail"]
    
    async def test_compile_contract_missing_chat_id(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test contract compilation without chatId"""
        
        compile_data = {}
        
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
                "/api/v1/compile-contract",
                json=compile_data,
                headers={"Authorization": f"Bearer {valid_jwt_token}"}
            )
            
            # Should return 422 (validation error)
            assert response.status_code == 422
    
    async def test_compile_contract_invalid_token(self, async_client: AsyncClient):
        """Test contract compilation with invalid token"""
        
        compile_data = {
            "chatId": "test-chat-id-123"
        }
        
        with patch('src.api.router.contract.JWTService.verify_token', new_callable=AsyncMock) as mock_verify:
            mock_verify.side_effect = Exception("Invalid token")
            
            # Make request with invalid token
            response = await async_client.post(
                "/api/v1/compile-contract",
                json=compile_data,
                headers={"Authorization": "Bearer invalid_token"}
            )
            
            # Should return 401
            assert response.status_code == 401
            assert "Authentication required" in response.json()["detail"]
    
    async def test_compile_contract_external_service_error(self, async_client: AsyncClient, valid_jwt_token: str):
        """Test contract compilation when external service fails"""
        
        compile_data = {
            "chatId": "test-chat-id-123"
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
            
            # Mock httpx to simulate external service error
            with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
                mock_response = AsyncMock()
                mock_response.status_code = 500
                mock_response.text = "Internal server error"
                mock_post.return_value = mock_response
                
                # Make request
                response = await async_client.post(
                    "/api/v1/compile-contract",
                    json=compile_data,
                    headers={"Authorization": f"Bearer {valid_jwt_token}"}
                )
                
                # Should return 502 (Bad Gateway)
                assert response.status_code == 502
                assert "temporarily unavailable" in response.json()["detail"]
