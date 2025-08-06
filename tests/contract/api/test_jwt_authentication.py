from fastapi.testclient import TestClient
import jwt
from datetime import datetime, timedelta

from src.app import create_app
from src.infra.config.settings import settings

client = TestClient(create_app())

def create_test_token(expired=False, invalid_signature=False):
    """Helper function to create test JWT tokens"""
    exp = datetime.utcnow() - timedelta(minutes=5) if expired else datetime.utcnow() + timedelta(minutes=30)
    payload = {
        "sub": "test@example.com",
        "exp": exp,
        "iat": datetime.utcnow(),
        "scope": "user"
    }
    secret = "wrong-secret" if invalid_signature else settings.JWT_SECRET_KEY
    return jwt.encode(payload, secret, algorithm=settings.JWT_ALGORITHM)

def test_protected_endpoint_without_token():
    """Test accessing protected endpoint without token returns 401"""
    response = client.get("/api/v1/protected")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "Not authenticated"

def test_protected_endpoint_with_valid_token():
    """Test accessing protected endpoint with valid token succeeds"""
    token = create_test_token()
    response = client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"

def test_protected_endpoint_with_expired_token():
    """Test accessing protected endpoint with expired token returns 401"""
    token = create_test_token(expired=True)
    response = client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "token has expired" in data["detail"].lower()
    assert "refresh" in data["detail"].lower()

def test_protected_endpoint_with_invalid_signature():
    """Test accessing protected endpoint with invalid signature returns 403"""
    token = create_test_token(invalid_signature=True)
    response = client.get(
        "/api/v1/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert "invalid signature" in data["detail"].lower()