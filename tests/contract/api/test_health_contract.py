import pytest
from fastapi.testclient import TestClient
from src.app import create_app

client = TestClient(create_app())

def test_health_check_contract():
    """Contract test for health check endpoint
    Verifies the response schema and format matches the API contract
    """
    response = client.get("/api/v1/health")
    
    # Contract assertions
    data = response.json()
    
    # Schema validation
    assert isinstance(data, dict)
    assert "status" in data
    assert "service" in data
    assert "version" in data
    
    # Type validation
    assert isinstance(data["status"], str)
    assert isinstance(data["service"], str)
    assert isinstance(data["version"], str)
    
    # Value validation
    assert data["status"] in ["healthy", "unhealthy"]  # Defined in API contract
    assert data["service"] == "api_gateway"  # Service identifier as per contract