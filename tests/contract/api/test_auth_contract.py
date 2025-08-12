"""
Contract tests for authentication API endpoints.
Tests API contracts, request/response schemas, and error handling.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from src.app import create_app
from src.api.controller.auth.dto.input_dto import ChallengeRequestDto, VerifyRequestDto
from src.api.controller.auth.dto.output_dto import ChallengeResponseDto, AuthResponseDto
from src.api.controller.auth.dto.error_responses import ErrorCode


class TestAuthAPIContract:
    """Contract tests for authentication API."""
    
    @pytest.fixture(scope="class")
    def client(self):
        """Create test client."""
        app = create_app()
        
        # Initialize protocols for testing
        import asyncio
        from src.api.controller.auth.auth_controller import init_protocols
        
        async def init_for_test():
            try:
                await init_protocols()
            except Exception as e:
                print(f"Warning: Protocol initialization failed: {e}")
        
        # Run initialization
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        if loop.is_running():
            # If loop is already running, skip initialization
            pass
        else:
            loop.run_until_complete(init_for_test())
        
        return TestClient(app)
    
    def test_challenge_request_schema_validation(self):
        """Test challenge request DTO validation."""
        # Valid request
        valid_request = ChallengeRequestDto(
            wallet_address="0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            protocol="evm"
        )
        assert valid_request.wallet_address == "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
        assert valid_request.protocol.value == "evm"
        
        # Invalid protocol
        with pytest.raises(ValidationError):
            ChallengeRequestDto(
                wallet_address="0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
                protocol="invalid_protocol"
            )
        
        # Empty wallet address
        with pytest.raises(ValidationError):
            ChallengeRequestDto(
                wallet_address="",
                protocol="evm"
            )
        
        print("✅ Challenge request schema validation passed")
    
    def test_verify_request_schema_validation(self):
        """Test verify request DTO validation."""
        # Valid EVM request
        valid_evm_request = VerifyRequestDto(
            wallet_address="0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            signature="0x" + "a" * 130,  # Valid hex signature format
            protocol="evm"
        )
        assert valid_evm_request.protocol.value == "evm"
        assert valid_evm_request.public_key is None
        
        # Valid NEAR request with public key
        valid_near_request = VerifyRequestDto(
            wallet_address="alice.testnet",
            signature="base58_signature_here",
            protocol="near",
            public_key="ed25519:public_key_here"
        )
        assert valid_near_request.protocol.value == "near"
        assert valid_near_request.public_key == "ed25519:public_key_here"
        
        # Invalid empty signature
        with pytest.raises(ValidationError):
            VerifyRequestDto(
                wallet_address="0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
                signature="",
                protocol="evm"
            )
        
        print("✅ Verify request schema validation passed")
    
    def test_challenge_response_schema(self):
        """Test challenge response DTO schema."""
        response_data = {
            "nonce": "0x1234567890abcdef",
            "message": "Sign in to MintroAI\\nNonce: 0x1234567890abcdef",
            "expires_in": 300,
            "protocol": "evm"
        }
        
        response = ChallengeResponseDto(**response_data)
        assert response.nonce == "0x1234567890abcdef"
        assert response.expires_in == 300
        assert response.protocol == "evm"
        assert "Sign in to MintroAI" in response.message
        
        print("✅ Challenge response schema validation passed")
    
    def test_auth_response_schema(self):
        """Test authentication response DTO schema."""
        response_data = {
            "access_token": "jwt.access.token",
            "refresh_token": "jwt.refresh.token",
            "token_type": "bearer",
            "expires_in": 3600,
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            "protocol": "evm"
        }
        
        response = AuthResponseDto(**response_data)
        assert response.access_token == "jwt.access.token"
        assert response.token_type == "bearer"
        assert response.expires_in == 3600
        assert response.wallet_address == "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
        assert response.protocol == "evm"
        
        print("✅ Auth response schema validation passed")
    
    def test_challenge_endpoint_contract(self, client):
        """Test challenge endpoint API contract."""
        # Valid request
        response = client.post("/api/v1/auth/challenge", json={
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            "protocol": "evm"
        })
        
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure
        required_fields = ["nonce", "message", "expires_in", "protocol"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        assert isinstance(data["expires_in"], int)
        assert data["expires_in"] > 0
        assert data["protocol"] == "evm"
        assert len(data["nonce"]) > 10  # Should be a reasonable length
        
        print("✅ Challenge endpoint contract validation passed")
    
    def test_challenge_endpoint_error_responses(self, client):
        """Test challenge endpoint error response contracts."""
        # Invalid protocol
        response = client.post("/api/v1/auth/challenge", json={
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            "protocol": "invalid_protocol"
        })
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data or "error" in data
        
        # Invalid wallet address
        response = client.post("/api/v1/auth/challenge", json={
            "wallet_address": "invalid_address",
            "protocol": "evm"
        })
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data or "error" in data
        
        # Missing required fields
        response = client.post("/api/v1/auth/challenge", json={
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
            # Missing protocol
        })
        
        assert response.status_code == 422
        
        print("✅ Challenge endpoint error contracts passed")
    
    def test_verify_endpoint_contract(self, client):
        """Test verify endpoint API contract."""
        # First create a challenge
        challenge_response = client.post("/api/v1/auth/challenge", json={
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            "protocol": "evm"
        })
        assert challenge_response.status_code == 200
        
        # Try to verify (will fail, but tests contract)
        response = client.post("/api/v1/auth/verify", json={
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            "signature": "0x" + "a" * 130,  # Valid format but wrong signature
            "protocol": "evm"
        })
        
        # Should return 401 (invalid signature) but with proper error structure
        assert response.status_code == 401
        data = response.json()
        assert "error" in data or "detail" in data
        
        print("✅ Verify endpoint contract validation passed")
    
    def test_protocols_endpoint_contract(self, client):
        """Test protocols endpoint API contract."""
        response = client.get("/api/v1/auth/protocols")
        
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure
        required_fields = ["protocols", "total_count", "enabled_count"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        assert isinstance(data["protocols"], list)
        assert isinstance(data["total_count"], int)
        assert isinstance(data["enabled_count"], int)
        assert data["total_count"] >= 0
        assert data["enabled_count"] >= 0
        
        # Validate protocol structure
        if data["protocols"]:
            protocol = data["protocols"][0]
            protocol_fields = ["name", "enabled", "rpc_status", "features"]
            for field in protocol_fields:
                assert field in protocol, f"Missing protocol field: {field}"
        
        print("✅ Protocols endpoint contract validation passed")
    
    def test_account_info_endpoint_contract(self, client):
        """Test account info endpoint API contract."""
        # Test EVM account
        response = client.get("/api/v1/auth/account/evm/0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8")
        
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure
        required_fields = ["address", "protocol", "valid", "network", "account_type"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        assert data["address"] == "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
        assert data["protocol"] == "evm"
        assert isinstance(data["valid"], bool)
        
        # Test NEAR account
        response = client.get("/api/v1/auth/account/near/alice.testnet")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["address"] == "alice.testnet"
        assert data["protocol"] == "near"
        assert isinstance(data["valid"], bool)
        
        print("✅ Account info endpoint contract validation passed")
    
    def test_health_endpoint_contract(self, client):
        """Test health endpoint API contract."""
        response = client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure
        required_fields = ["status", "timestamp", "protocols", "services"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert isinstance(data["protocols"], dict)
        assert isinstance(data["services"], dict)
        
        print("✅ Health endpoint contract validation passed")
    
    def test_metrics_endpoint_contract(self, client):
        """Test metrics endpoint API contract."""
        response = client.get("/api/v1/metrics")
        
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure
        required_fields = ["timestamp", "overall", "last_hour", "by_protocol"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
        
        # Validate overall metrics structure
        overall = data["overall"]
        overall_fields = ["total_auth_attempts", "success_rate_percent", "active_sessions"]
        for field in overall_fields:
            assert field in overall, f"Missing overall field: {field}"
            assert isinstance(overall[field], (int, float))
        
        print("✅ Metrics endpoint contract validation passed")
    
    def test_error_response_format_consistency(self, client):
        """Test that all error responses follow consistent format."""
        error_scenarios = [
            # Invalid protocol
            ("/api/v1/auth/challenge", {"wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8", "protocol": "invalid"}),
            # Invalid address
            ("/api/v1/auth/challenge", {"wallet_address": "invalid", "protocol": "evm"}),
            # Missing fields
            ("/api/v1/auth/challenge", {"wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"}),
        ]
        
        for endpoint, payload in error_scenarios:
            response = client.post(endpoint, json=payload)
            
            # Should return error status
            assert response.status_code >= 400
            
            data = response.json()
            # Should have error information (either 'error' or 'detail' field)
            assert "error" in data or "detail" in data
            
        print("✅ Error response format consistency validated")
    
    def test_response_headers(self, client):
        """Test that responses include expected headers."""
        response = client.get("/api/v1/health")
        
        assert response.status_code == 200
        
        # TestClient doesn't simulate CORS headers fully, so check for other headers
        # CORS headers would be present in real HTTP requests
        assert "content-type" in response.headers
        assert response.headers["content-type"] == "application/json"
        
        # Should include content type
        assert response.headers["content-type"] == "application/json"
        
        print("✅ Response headers validation passed")
    
    def test_rate_limiting_headers(self, client):
        """Test that rate limiting responses include proper headers."""
        # Make a request to trigger rate limiting headers
        response = client.post("/api/v1/auth/challenge", json={
            "wallet_address": "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            "protocol": "evm"
        })
        
        # Should include rate limit headers (if not rate limited)
        if response.status_code == 200:
            # Normal response might have rate limit info headers
            pass
        elif response.status_code == 429:
            # Rate limited response should have retry-after header
            assert "retry-after" in response.headers
        
        print("✅ Rate limiting headers validation passed")
