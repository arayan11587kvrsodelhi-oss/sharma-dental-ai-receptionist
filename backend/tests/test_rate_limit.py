"""Rate limiting tests for Sharma Dental AI."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient

# Import the app
import sys
import os
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-secret-key")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon-key")

from backend.app.main import app, limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from fastapi import Request

# Test client
client = TestClient(app)


class TestLimiterConfiguration:
    """Tests for limiter configuration."""

    def test_limiter_initialized(self):
        """Limiter should be initialized on app state."""
        assert hasattr(app.state, "limiter")
        assert hasattr(app.state.limiter, "_default_limits")
        assert app.state.limiter._default_limits is not None

    def test_rate_limit_exception_handler_exists(self):
        """Rate limit exception handler should be registered."""
        assert RateLimitExceeded in app.exception_handlers


class TestRateLimitKeyFunction:
    """Tests for rate limit key function."""

    def test_get_remote_address_works(self):
        """get_remote_address should extract client IP."""
        from slowapi.util import get_remote_address
        from fastapi import Request

        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "192.168.1.1"

        ip = get_remote_address(mock_request)
        assert ip == "192.168.1.1"

    def test_get_remote_address_fallback(self):
        """get_remote_address should fallback if client is None."""
        from slowapi.util import get_remote_address
        from fastapi import Request

        mock_request = MagicMock(spec=Request)
        mock_request.client = None

        ip = get_remote_address(mock_request)
        # slowapi falls back to testclient's IP
        assert ip is not None
        assert isinstance(ip, str)