from fastapi.testclient import TestClient
import pytest
from datetime import datetime, timedelta

from src.app import create_app
from src.infra.config.settings import settings

@pytest.fixture
def client():
    """Create a new test client for each test"""
    return TestClient(create_app())

def test_rate_limit_exceeded(client):
    """Test rate limiting kicks in after too many requests"""
    # Make multiple requests to exceed rate limit
    for _ in range(settings.RATE_LIMIT_MAX_REQUESTS):
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    # Next request should be rate limited
    response = client.get("/api/v1/health")
    assert response.status_code == 429
    assert "retry-after" in response.headers
    assert "Too many requests" in response.json()["detail"]

def test_suspicious_ip_blocking(client):
    """Test suspicious IP gets blocked after suspicious activity"""
    # Simulate suspicious activity with invalid wallet signatures
    mock_data = {
        "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "signature": "invalid_signature"
    }
    
    # Make multiple failed attempts
    for _ in range(settings.SUSPICIOUS_IP_THRESHOLD):
        response = client.post(
            "/api/v1/test/wallet-verify",
            json=mock_data
        )
        assert response.status_code in [401, 403]

    try:
        # Next request from same IP should be blocked
        response = client.get("/api/v1/health")
        pytest.fail("Request should have been blocked")
    except Exception as e:
        assert "IP has been temporarily blocked" in str(e)
        assert "403" in str(e)

def test_cors_headers(client):
    """Test CORS headers are properly set for allowed origins"""
    headers = {
        "Origin": settings.ALLOWED_ORIGINS[0],
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "content-type,authorization",
    }
    response = client.options("/api/v1/health", headers=headers)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == settings.ALLOWED_ORIGINS[0]
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()
    assert "authorization" in response.headers["access-control-allow-headers"].lower()

def test_request_validation(client):
    """Test invalid request data returns proper validation errors"""
    invalid_data = {
        "wallet_address": "invalid-address",  # Invalid Ethereum address format
        "signature": "0x123"
    }
    response = client.post("/api/v1/test/wallet-verify", json=invalid_data)
    assert response.status_code == 422  # FastAPI's validation error status code
    errors = response.json()
    assert "detail" in errors
    assert isinstance(errors["detail"], list)  # Pydantic validation errors