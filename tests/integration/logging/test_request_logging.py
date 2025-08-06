from fastapi.testclient import TestClient
import pytest
import json
import logging
from datetime import datetime
import sys
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.app import create_app
from src.infra.config.settings import settings

@pytest.fixture
def client():
    """Create a new test client for each test"""
    return TestClient(create_app())

@pytest.fixture(autouse=True)
def setup_logging(caplog):
    """Setup logging to capture logs in tests"""
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("MintroAI")
    logger.propagate = True
    yield
    logger.propagate = True

def get_json_logs(caplog):
    """Extract JSON logs from caplog output"""
    logs = []
    for record in caplog.records:
        try:
            if isinstance(record.msg, dict):
                logs.append(record.msg)
            elif isinstance(record.msg, str) and record.msg.startswith("{"):
                logs.append(json.loads(record.msg))
        except (json.JSONDecodeError, AttributeError):
            continue
    return logs

def test_request_logging(client, caplog):
    """Test that API requests are logged with correlation ID"""
    correlation_id = "test-correlation-id"
    response = client.get(
        "/api/v1/health",
        headers={"X-Request-ID": correlation_id}
    )
    assert response.status_code == 200
    
    # Get JSON logs
    logs = get_json_logs(caplog)
    assert len(logs) > 0
    
    # Find request log
    request_logs = [log for log in logs if correlation_id in str(log)]
    assert len(request_logs) >= 2  # Health check log and request log
    
    # Check request log
    request_log = next((log for log in request_logs if "method" in str(log)), None)
    assert request_log is not None
    assert correlation_id in str(request_log)
    assert "GET" in str(request_log)
    assert "/api/v1/health" in str(request_log)

def test_error_logging(client, caplog):
    """Test that errors are logged with stack trace and context"""
    # Trigger a validation error
    response = client.post(
        "/api/v1/test/wallet-verify",
        json={"invalid": "data"}
    )
    assert response.status_code == 422
    
    # Get JSON logs
    logs = get_json_logs(caplog)
    assert len(logs) > 0
    
    # Find error log
    error_log = next((log for log in logs if "422" in str(log)), None)
    assert error_log is not None
    assert "422" in str(error_log)
    assert "request_id" in str(error_log)

def test_performance_metrics_logging(client, caplog):
    """Test that performance metrics are logged"""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    
    # Get JSON logs
    logs = get_json_logs(caplog)
    assert len(logs) > 0
    
    # Find request log with performance metrics
    perf_log = next((log for log in logs if "duration_ms" in str(log)), None)
    assert perf_log is not None
    assert "duration_ms" in str(perf_log)
    assert "timestamp" in str(perf_log)

def test_health_check_logging(client, caplog):
    """Test that health checks are logged with service status"""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    
    # Get JSON logs
    logs = get_json_logs(caplog)
    assert len(logs) > 0
    
    # Find health check log
    health_log = next((log for log in logs if "health_check" in str(log)), None)
    assert health_log is not None
    assert "healthy" in str(health_log)
    assert "dependencies" in str(health_log)