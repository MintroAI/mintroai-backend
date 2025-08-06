import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from redis.asyncio import Redis

from src.core.service.auth.cache.token_store import TokenStore
from fastapi import HTTPException, status
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from src.core.logger.logger import get_logger
from src.core.service.auth.models.token import TokenPayload, TokenResponse, TokenType
from src.infra.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class JWTService:
    """Service for handling JWT token operations"""

    def __init__(self, redis_client: Redis):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = "HS256"
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
        self.token_store = TokenStore(redis_client)

    def _create_token(
        self,
        wallet_address: str,
        token_type: TokenType,
        expires_delta: Optional[timedelta] = None
    ) -> tuple[str, datetime]:
        """
        Create a JWT token with the given parameters
        Returns the token string and its expiration datetime
        """
        if expires_delta is None:
            if token_type == TokenType.ACCESS:
                expires_delta = timedelta(minutes=self.access_token_expire_minutes)
            else:
                expires_delta = timedelta(days=self.refresh_token_expire_days)

        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + expires_delta

        token_jti = str(uuid.uuid4())

        to_encode = TokenPayload(
            wallet_address=wallet_address,
            exp=expires_at,
            iat=issued_at,
            type=token_type,
            jti=token_jti
        )

        encoded_jwt = jwt.encode(
            to_encode.model_dump(),
            self.secret_key,
            algorithm=self.algorithm
        )

        return encoded_jwt, expires_at

    async def create_tokens(self, wallet_address: str) -> TokenResponse:
        """Generate new access and refresh token pair"""
        access_token, access_exp = self._create_token(
            wallet_address=wallet_address,
            token_type=TokenType.ACCESS
        )

        refresh_token, _ = self._create_token(
            wallet_address=wallet_address,
            token_type=TokenType.REFRESH
        )

        # Calculate seconds until access token expires
        expires_in = int((access_exp - datetime.now(timezone.utc)).total_seconds())

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in
        )

    async def verify_token(self, token: str, expected_type: TokenType) -> TokenPayload:
        """
        Verify a JWT token and return its payload
        Raises HTTPException if token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            token_data = TokenPayload(**payload)

            # Verify token type matches expected
            if token_data.type != expected_type:
                logger.warning(
                    "Token type mismatch",
                    extra={
                        "expected_type": expected_type,
                        "actual_type": token_data.type,
                        "wallet_address": token_data.wallet_address
                    }
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )

            # Check if token is blacklisted
            if await self.token_store.is_blacklisted(token_data.jti):
                logger.warning(
                    "Blacklisted token used",
                    extra={
                        "jti": token_data.jti,
                        "wallet_address": token_data.wallet_address
                    }
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )

            return token_data

        except ExpiredSignatureError:
            logger.info(
                "Token expired",
                extra={"token_type": expected_type}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )

        except InvalidTokenError as e:
            logger.warning(
                "Invalid token",
                extra={
                    "token_type": expected_type,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

    async def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        """
        Generate new access token using a valid refresh token
        Also rotates the refresh token for security
        """
        # Verify the refresh token
        token_data = await self.verify_token(refresh_token, TokenType.REFRESH)

        # Generate new token pair
        new_tokens = await self.create_tokens(token_data.wallet_address)

        # Blacklist the used refresh token
        await self.token_store.add_to_blacklist(
            jti=token_data.jti,
            exp=token_data.exp,
            reason="Refresh token rotation"
        )

        return new_tokens

    async def revoke_token(self, token: str, reason: Optional[str] = None) -> None:
        """
        Revoke a token by adding it to the blacklist
        This can be used for both access and refresh tokens
        """
        try:
            # Decode without verification to get JTI and expiry
            # We want to be able to blacklist even if the token is already expired
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            token_data = TokenPayload(**payload)

            await self.token_store.add_to_blacklist(
                jti=token_data.jti,
                exp=token_data.exp,
                reason=reason
            )

        except Exception as e:
            logger.error(
                "Failed to revoke token",
                extra={"error": str(e)}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token format"
            )