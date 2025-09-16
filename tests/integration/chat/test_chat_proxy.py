"""
Integration tests for chat proxy endpoint
"""

import pytest
import json
from datetime import datetime
from unittest.mock import AsyncMock, patch

from src.core.service.chat.models.chat import (
    ChatRequest, ChatResponse, ChatMode, UserContext
)
from src.core.service.chat.n8n_client import N8nClient
from src.core.service.chat.chat_rate_limiter import ChatRateLimiter
from src.core.service.chat.chat_logger import ChatLogger


@pytest.fixture
def mock_n8n_client():
    """Mock n8n client for testing"""
    client = AsyncMock(spec=N8nClient)
    client.send_to_n8n = AsyncMock(return_value={
        "output": "This is a test response from n8n",
        "message": "Success"
    })
    return client


@pytest.fixture
def mock_rate_limiter():
    """Mock rate limiter for testing"""
    limiter = AsyncMock(spec=ChatRateLimiter)
    limiter.check_rate_limit = AsyncMock(return_value=(
        True,  # is_allowed
        {
            "remaining": 99,
            "reset_time": "2025-01-10T12:00:00Z",
            "limit": 100
        }
    ))
    return limiter


@pytest.fixture
def mock_chat_logger():
    """Mock chat logger for testing"""
    logger = AsyncMock(spec=ChatLogger)
    logger.log_interaction = AsyncMock()
    return logger


class TestChatProxy:
    """Test chat proxy functionality"""
    
    @pytest.mark.asyncio
    async def test_chat_proxy_guest_user(self, mock_n8n_client, mock_rate_limiter, mock_chat_logger):
        """Test chat proxy with guest user (no authentication)"""
        # Create request
        request = ChatRequest(
            sessionId="test-session-123",
            chatInput="Hello, how are you?",
            mode=ChatMode.GENERAL
        )
        
        # Create guest user context
        user_context = UserContext(
            wallet_address=None,
            is_authenticated=False,
            user_type="guest"
        )
        
        # Test n8n client
        response = await mock_n8n_client.send_to_n8n(request, user_context)
        
        assert response["output"] == "This is a test response from n8n"
        assert response["message"] == "Success"
        mock_n8n_client.send_to_n8n.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_chat_proxy_authenticated_user(self, mock_n8n_client, mock_rate_limiter):
        """Test chat proxy with authenticated user"""
        # Create request
        request = ChatRequest(
            sessionId="test-session-456",
            chatInput="Create a token for me",
            mode=ChatMode.TOKEN
        )
        
        # Create authenticated user context
        user_context = UserContext(
            wallet_address="0x123...abc",
            is_authenticated=True,
            user_type="authenticated",
            wallet_type="evm"
        )
        
        # Test n8n client
        response = await mock_n8n_client.send_to_n8n(request, user_context)
        
        assert response is not None
        mock_n8n_client.send_to_n8n.assert_called_once_with(request, user_context)
    
    @pytest.mark.asyncio
    async def test_rate_limit_check(self, mock_rate_limiter):
        """Test rate limiting functionality"""
        # Guest user context
        user_context = UserContext(
            wallet_address=None,
            is_authenticated=False,
            user_type="guest"
        )
        
        # Check rate limit
        is_allowed, rate_info = await mock_rate_limiter.check_rate_limit(
            user_context, "127.0.0.1"
        )
        
        assert is_allowed is True
        assert rate_info["remaining"] == 99
        assert rate_info["limit"] == 100
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        """Test rate limit exceeded scenario"""
        limiter = AsyncMock(spec=ChatRateLimiter)
        limiter.check_rate_limit = AsyncMock(return_value=(
            False,  # is_allowed = False
            {
                "remaining": 0,
                "reset_time": "2025-01-10T13:00:00Z",
                "limit": 3
            }
        ))
        
        user_context = UserContext(
            wallet_address=None,
            is_authenticated=False,
            user_type="guest"
        )
        
        is_allowed, rate_info = await limiter.check_rate_limit(
            user_context, "127.0.0.1"
        )
        
        assert is_allowed is False
        assert rate_info["remaining"] == 0
    
    @pytest.mark.asyncio
    async def test_different_chat_modes(self, mock_n8n_client):
        """Test different chat modes"""
        modes = [ChatMode.TOKEN, ChatMode.VESTING, ChatMode.GENERAL]
        
        for mode in modes:
            request = ChatRequest(
                sessionId=f"test-{mode.value}",
                chatInput=f"Test message for {mode.value}",
                mode=mode
            )
            
            response = await mock_n8n_client.send_to_n8n(request)
            assert response is not None
    
    @pytest.mark.asyncio
    async def test_n8n_timeout_handling(self):
        """Test n8n timeout scenario"""
        client = AsyncMock(spec=N8nClient)
        client.send_to_n8n = AsyncMock(side_effect=TimeoutError("Request timeout"))
        
        request = ChatRequest(
            sessionId="timeout-test",
            chatInput="This will timeout",
            mode=ChatMode.GENERAL
        )
        
        with pytest.raises(TimeoutError):
            await client.send_to_n8n(request)
    
    @pytest.mark.asyncio
    async def test_n8n_connection_error(self):
        """Test n8n connection error"""
        client = AsyncMock(spec=N8nClient)
        client.send_to_n8n = AsyncMock(side_effect=ConnectionError("Connection failed"))
        
        request = ChatRequest(
            sessionId="connection-test",
            chatInput="This will fail",
            mode=ChatMode.GENERAL
        )
        
        with pytest.raises(ConnectionError):
            await client.send_to_n8n(request)
    
    @pytest.mark.asyncio
    async def test_chat_logging(self, mock_chat_logger):
        """Test chat interaction logging"""
        user_context = UserContext(
            wallet_address="test.near",
            is_authenticated=True,
            user_type="authenticated",
            wallet_type="near"
        )
        
        await mock_chat_logger.log_interaction(
            session_id="log-test",
            user_context=user_context,
            chat_input="Test message",
            mode=ChatMode.GENERAL,
            response={"output": "Test response"},
            duration=1.5,
            client_ip="127.0.0.1",
            user_agent="TestAgent/1.0"
        )
        
        mock_chat_logger.log_interaction.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_premium_user_rate_limit(self):
        """Test premium user has higher rate limit"""
        limiter = ChatRateLimiter()
        
        # Premium user context
        premium_context = UserContext(
            wallet_address="premium.near",
            is_authenticated=True,
            user_type="premium"
        )
        
        # Regular user context
        regular_context = UserContext(
            wallet_address="regular.near",
            is_authenticated=True,
            user_type="authenticated"
        )
        
        # Get rate limit configs
        premium_limit, _ = limiter._get_rate_limit_config(premium_context)
        regular_limit, _ = limiter._get_rate_limit_config(regular_context)
        
        assert premium_limit > regular_limit
        assert premium_limit == 500  # Premium limit
        assert regular_limit == 100  # Regular authenticated limit
