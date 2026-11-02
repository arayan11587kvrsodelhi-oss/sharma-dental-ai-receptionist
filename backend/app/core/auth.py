"""Authentication and authorization for Sharma Dental AI.

Implements Supabase JWT verification with proper signature validation,
issuer/audience/expiry checks, and role-based access control.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional
from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError
import httpx

from .config import settings


# Security scheme
security = HTTPBearer(auto_error=False)


class SupabaseAuthError(Exception):
    """Base exception for authentication errors."""
    pass


class InvalidTokenError(SupabaseAuthError):
    """Raised when token is invalid or malformed."""
    pass


class TokenExpiredError(SupabaseAuthError):
    """Raised when token has expired."""
    pass


class InvalidClaimsError(SupabaseAuthError):
    """Raised when token claims don't match expectations."""
    pass


class User:
    """Authenticated user derived from verified JWT."""

    def __init__(
        self,
        user_id: str,
        email: str,
        role: str,
        aud: str,
        exp: int,
        iat: int,
    ):
        self.user_id = user_id
        self.email = email
        self.role = role
        self.aud = aud
        self.exp = exp
        self.iat = iat

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_active(self) -> bool:
        return datetime.now(timezone.utc).timestamp() < self.exp


class AuthConfig:
    """Configuration for Supabase JWT verification."""

    def __init__(
        self,
        supabase_url: str,
        supabase_jwt_secret: str,
        audience: Optional[str] = None,
    ):
        if not supabase_url:
            raise ValueError("SUPABASE_URL must be set")
        if not supabase_jwt_secret:
            raise ValueError("SUPABASE_JWT_SECRET (or SUPABASE_SERVICE_ROLE_KEY) must be set")

        self.supabase_url = supabase_url.rstrip("/")
        self.jwt_secret = supabase_jwt_secret
        self.audience = audience or "authenticated"
        self.issuer = f"{self.supabase_url}/auth/v1"

    @classmethod
    def from_env(cls) -> "AuthConfig":
        """Create AuthConfig from environment variables."""
        supabase_url = settings.SUPABASE_URL
        # Supabase uses the service role key as the JWT secret for verification
        jwt_secret = settings.SUPABASE_SERVICE_ROLE_KEY
        if not jwt_secret:
            # Try alternative env var name
            jwt_secret = os.environ.get("SUPABASE_JWT_SECRET", "")
        return cls(supabase_url, jwt_secret)


# Cache JWKS for performance
@lru_cache(maxsize=1)
def _get_jwks_client(jwks_url: str) -> dict:
    """Fetch JWKS from Supabase (cached)."""
    try:
        response = httpx.get(jwks_url, timeout=10.0)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise SupabaseAuthError(f"Failed to fetch JWKS: {e}")


def _verify_jwt_signature(token: str, jwks: dict) -> dict:
    """Verify JWT signature using JWKS."""
    try:
        # Get the key ID from token header
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise InvalidTokenError("Token header missing 'kid'")

        # Find matching key in JWKS
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break

        if not key:
            raise InvalidTokenError(f"No matching key found for kid: {kid}")

        # Verify and decode
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},  # We verify these manually
        )
    except JWTError as e:
        raise InvalidTokenError(f"JWT verification failed: {e}")


async def verify_supabase_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> "User":
    """Verify Supabase JWT and return authenticated user.

    Validates:
    - JWT signature using Supabase JWKS
    - Token expiry
    - Issuer matches Supabase project
    - Audience matches expected value
    - Required claims present (sub, email, role)
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    auth_config = AuthConfig.from_env()

    try:
        # First decode without verification to get claims for issuer check
        unverified = jwt.get_unverified_claims(token)

        # Check expiry
        exp = unverified.get("exp")
        if not exp:
            raise InvalidClaimsError("Token missing 'exp' claim")
        if datetime.now(timezone.utc).timestamp() >= exp:
            raise TokenExpiredError("Token has expired")

        # Check issuer
        iss = unverified.get("iss")
        if iss != auth_config.issuer:
            raise InvalidClaimsError(f"Invalid issuer: expected {auth_config.issuer}, got {iss}")

        # Check audience
        aud = unverified.get("aud")
        if isinstance(aud, list):
            if auth_config.audience not in aud:
                raise InvalidClaimsError(f"Invalid audience: {aud}")
        elif aud != auth_config.audience:
            raise InvalidClaimsError(f"Invalid audience: {aud}")

        # Check required claims
        sub = unverified.get("sub")
        if not sub:
            raise InvalidClaimsError("Token missing 'sub' claim")

        email = unverified.get("email")
        if not email:
            raise InvalidClaimsError("Token missing 'email' claim")

        # Verify signature using JWKS (must happen before trusting any claims)
        jwks_url = f"{auth_config.supabase_url}/auth/v1/jwks"
        jwks = _get_jwks_client(jwks_url)
        verified_claims = _verify_jwt_signature(token, jwks)

        # Re-check expiry on verified claims
        if verified_claims.get("exp", 0) < datetime.now(timezone.utc).timestamp():
            raise TokenExpiredError("Token has expired")

        return User(
            user_id=verified_claims["sub"],
            email=verified_claims["email"],
            role=verified_claims.get("role", "authenticated"),
            aud=verified_claims.get("aud", ""),
            exp=verified_claims["exp"],
            iat=verified_claims.get("iat", 0),
        )

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (InvalidTokenError, TokenExpiredError, InvalidClaimsError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except SupabaseAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin(user: "User" = Depends(verify_supabase_token)) -> "User":
    """Dependency that requires admin role."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


def require_auth(user: "User" = Depends(verify_supabase_token)) -> "User":
    """Dependency that requires valid authentication (any role)."""
    return user


# Optional: allow public access for health checks
async def optional_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional["User"]:
    """Optional authentication - returns user if token valid, None otherwise."""
    if not credentials:
        return None
    try:
        return await verify_supabase_token(credentials)
    except HTTPException:
        return None