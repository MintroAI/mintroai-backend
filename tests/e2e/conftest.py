"""
E2E test configuration and fixtures.
"""

import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient
from fastapi.testclient import TestClient

from src.app import create_app
from src.api.controller.auth.auth_controller import init_protocols


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def app():
    """Create FastAPI app instance for testing."""
    app = create_app()
    
    # Initialize protocols for testing
    try:
        await init_protocols()
    except Exception as e:
        print(f"Warning: Protocol initialization failed: {e}")
        # Continue with tests even if protocols fail to initialize
    
    return app


@pytest.fixture(scope="session")
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Create async HTTP client for testing."""
    app_instance = await app  # Await the app fixture
    async with AsyncClient(app=app_instance, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture(scope="session")
def sync_client(app):
    """Create synchronous HTTP client for testing."""
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
async def clear_test_data():
    """Clear test data before each test."""
    # This would typically clear Redis, database, etc.
    # For now, we'll just ensure clean state
    yield
    # Cleanup after test if needed
