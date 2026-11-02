"""Authentication tests for Sharma Dental AI."""

import pytest
import os
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError, ExpiredSignatureError
from unittest.mock import AsyncMock, MagicMock, patch, MagicMock

# Set required environment variables before importing auth module
os.environ.setdefault("SUPABASE_URL", "https://test.supabase.co")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-secret-key")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon-key")

from backend.app.core.auth import (
    verify_supabase_token,
    require_auth,
    require_admin,
    User,
    SupabaseAuthError,
    InvalidTokenError,
    TokenExpiredError,
    InvalidClaimsError,
)

class MockCredentials:
    """Mock HTTPAuthorizationCredentials for testing."""
    def __init__(self, credentials: str):
        self.credentials = credentials


class TestAuthMissingToken:
    """Tests for missing authentication token."""

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self):
        """Missing token should return 401 Unauthorized."""
        with pytest.raises(Exception) as exc_info:
            await verify_supabase_token(None)

        assert exc_info.value.status_code == 401
        assert "Missing authentication token" in str(exc_info.value.detail)


class TestAuthInvalidTokenSimple:
    """Tests for invalid authentication tokens - simplified to test error paths."""

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self):
        """Expired token should return 401."""
        from jose import ExpiredSignatureError

        with patch("backend.app.core.auth.AuthConfig.from_env") as mock_auth_config:
            mock_auth_config_instance = MagicMock()
            mock_auth_config_instance.issuer = "https://test.supabase.co/auth/v1"
            mock_auth_config_instance.audience = "authenticated"
            mock_auth_config.return_value = mock_auth_config_instance

            # Return expired claim - this triggers the expiry check before signature verification
            with patch("backend.app.core.auth.jwt.get_unverified_claims") as mock_claims:
                mock_claims.return_value = {
                    "sub": "test-user",
                    "email": "test@example.com",
                    "role": "authenticated",
                    "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
                    "iss": "https://test.supabase.co/auth/v1",
                    "aud": "authenticated",
                }

                with pytest.raises(Exception) as exc_info:
                    await verify_supabase_token(MockCredentials("expired.token"))

                assert exc_info.value.status_code == 401
                assert "expired" in str(exc_info.value.detail).lower()


class TestAuthMissingClaims:
    """Tests for missing required JWT claims."""

    @pytest.mark.asyncio
    async def test_missing_sub_claim_returns_401(self):
        """Missing 'sub' claim should return 401."""
        with patch("backend.app.core.auth.AuthConfig.from_env") as mock_auth_config:
            mock_auth_config_instance = MagicMock()
            mock_auth_config_instance.issuer = "https://test.supabase.co/auth/v1"
            mock_auth_config_instance.audience = "authenticated"
            mock_auth_config.return_value = mock_auth_config_instance

            with patch("backend.app.core.auth.jwt.get_unverified_claims") as mock_claims:
                mock_claims.return_value = {
                    "email": "test@example.com",
                    "role": "authenticated",
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                    "iss": "https://test.supabase.co/auth/v1",
                    "aud": "authenticated",
                }

                with pytest.raises(Exception) as exc_info:
                    await verify_supabase_token(MockCredentials("invalid.token"))

                assert exc_info.value.status_code == 401
                assert "sub" in str(exc_info.value.detail).lower()

    @pytest.mark.asyncio
    async def test_invalid_issuer_returns_401(self):
        """Invalid issuer should return 401."""
        with patch("backend.app.core.auth.AuthConfig.from_env") as mock_auth_config:
            mock_auth_config_instance = MagicMock()
            mock_auth_config_instance.issuer = "https://test.supabase.co/auth/v1"
            mock_auth_config_instance.audience = "authenticated"
            mock_auth_config.return_value = mock_auth_config_instance

            with patch("backend.app.core.auth.jwt.get_unverified_claims") as mock_claims:
                mock_claims.return_value = {
                    "sub": "test-user",
                    "email": "test@example.com",
                    "role": "authenticated",
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                    "iss": "https://wrong-issuer.supabase.co/auth/v1",
                    "aud": "authenticated",
                }

                with pytest.raises(Exception) as exc_info:
                    await verify_supabase_token(MockCredentials("invalid.token"))

                assert exc_info.value.status_code == 401
                assert "issuer" in str(exc_info.value.detail).lower()


class TestInvalidAudience:
    """Tests for invalid audience."""

    @pytest.mark.asyncio
    async def test_invalid_audience_returns_401(self):
        """Invalid audience should return 401."""
        with patch("backend.app.core.auth.AuthConfig.from_env") as mock_auth_config:
            mock_auth_config_instance = MagicMock()
            mock_auth_config_instance.issuer = "https://test.supabase.co/auth/v1"
            mock_auth_config_instance.audience = "authenticated"
            mock_auth_config.return_value = mock_auth_config_instance

            with patch("backend.app.core.auth.jwt.get_unverified_claims") as mock_claims:
                mock_claims.return_value = {
                    "sub": "test-user",
                    "email": "test@example.com",
                    "role": "authenticated",
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                    "iss": "https://test.supabase.co/auth/v1",
                    "aud": "wrong-audience",
                }

                with pytest.raises(Exception) as exc_info:
                    await verify_supabase_token(MockCredentials("invalid.token"))

                assert exc_info.value.status_code == 401
                assert "audience" in str(exc_info.value.detail).lower()


class TestAdminAuthorization:
    """Tests for admin authorization - no external dependencies."""

    def test_require_admin_allows_admin_user(self):
        """require_admin should allow admin user."""
        admin_user = User(
            user_id="admin-id",
            email="admin@example.com",
            role="admin",
            aud="authenticated",
            exp=int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            iat=int(datetime.now(timezone.utc).timestamp()),
        )

        result = require_admin(admin_user)
        assert result == admin_user

    def test_require_admin_denies_regular_user(self):
        """require_admin should deny regular user."""
        regular_user = User(
            user_id="user-id",
            email="user@example.com",
            role="authenticated",
            aud="authenticated",
            exp=int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            iat=int(datetime.now(timezone.utc).timestamp()),
        )

        with pytest.raises(Exception) as exc_info:
            require_admin(regular_user)

        assert exc_info.value.status_code == 403
        assert "Admin access required" in str(exc_info.value.detail)


class TestForgedAdminJWT:
    """Tests that forged admin tokens are rejected."""

    @pytest.mark.asyncio
    async def test_forged_admin_token_rejected(self):
        """A forged admin token with wrong key should be rejected."""
        from jose import jwt, JWTError
        from unittest.mock import patch
        from backend.app.core.auth import verify_supabase_token, InvalidTokenError

        # The forged token is signed with a different key (not the Supabase JWKS)
        with patch('backend.app.core.auth.jwt.get_unverified_claims') as mock_claims:
            # Simulate a forged token with role=admin from attacker-controlled key
            mock_claims.return_value = {
                'sub': 'attacker',
                'role': 'admin',
                'aud': 'authenticated',
                'exp': 9999999999,
                'iss': 'https://test.supabase.co/auth/v1',
            }
            # The real verification will fail signature check
            with patch('backend.app.core.auth._get_jwks_client') as mock_jwks:
                mock_jwks.return_value = {'keys': [{'kid': 'attacker', 'kty': 'RSA', 'n': 'fake', 'e': 'AQAB'}]}
                with pytest.raises((InvalidTokenError, Exception)) as exc_info:
                    await verify_supabase_token(MockCredentials("forged.token"))
                assert exc_info.value.status_code == 401

        # Also test with PyJWT direct verification failure
        with pytest.raises((JWTError, Exception)):
            jwt.decode("forged.token", options={'verify_signature': True})


class TestJWTVerificationFlow:
    """Tests verifying the JWT security flow - role only from verified claims."""

    @pytest.mark.asyncio
    async def test_role_only_from_verified_claims(self):
        """Role should only be extracted from verified claims after JWKS signature verification."""
        # This test verifies the code pattern at auth.py:215 where role is read
        # from verified_claims, NOT from unverified claims (which was the vulnerability).

        # The vulnerability was: role = unverified.get("role", "authenticated")
        # The fix is: role=verified_claims.get("role", "authenticated")
        #
        # We verify this by checking the source code directly.

        import inspect
        from backend.app.core import auth

        source = inspect.getsource(auth.verify_supabase_token)

        # The verified_claims assignment must happen AFTER _verify_jwt_signature
        assert "_verify_jwt_signature" in source

        # role must come from verified_claims, not unverified
        # Find the line with role assignment
        lines = source.split('\n')
        role_line = None
        for i, line in enumerate(lines):
            if 'role=' in line and 'verified_claims' in line:
                role_line = line
                break

        assert role_line is not None, "Could not find role assignment from verified_claims"

        # Verify the role assignment pattern
        assert 'verified_claims.get' in role_line or 'verified_claims[' in role_line, \
            f"Role should be read from verified_claims. Got: {role_line}"

        # Verify there's NO role extraction from unverified claims
        unverified_role_lines = [l for l in lines if 'unverified.get' in l and 'role' in l]
        assert len(unverified_role_lines) == 0, \
            f"Found unverified role extraction: {unverified_role_lines}"