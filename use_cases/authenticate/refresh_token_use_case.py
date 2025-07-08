from dataclasses import dataclass
from typing import Dict, Any

from domain.entities.auth_token import AuthToken, TokenType
from domain.exceptions import (
    InvalidTokenException,
    TokenExpiredException,
    TokenRevokedException,
    UserNotFoundException,
    UserInactiveException
)
from interfaces.repositories.user_repository import UserRepositoryInterface
from interfaces.repositories.token_repository import TokenRepositoryInterface
from interfaces.services.jwt_service import JWTServiceInterface


@dataclass
class RefreshTokenRequest:
    """
    Request data structure for token refresh use case.

    Contains the refresh token provided by the client
    for generating a new access token.

    Attributes:
        refresh_token: JWT refresh token string
    """
    refresh_token: str


@dataclass
class RefreshTokenResponse:
    """
    Response data structure for token refresh use case.

    Contains the new access token and related metadata
    generated from the refresh token.

    Attributes:
        success: Whether token refresh was successful
        access_token: New JWT access token
        token_type: Type of token (typically "Bearer")
        expires_in: Access token expiration time in seconds
    """
    success: bool
    access_token: str
    token_type: str
    expires_in: int


class RefreshTokenUseCase:
    """
    Use case for handling token refresh operations.

    This use case encapsulates the business logic for refreshing access tokens
    using valid refresh tokens, including validation, token generation, and
    security checks to ensure only valid refresh tokens can generate new access tokens.

    It implements secure token rotation by validating the refresh token,
    checking user status, and generating new access tokens with proper expiration.
    """

    def __init__(self,
                 user_repository: UserRepositoryInterface,
                 token_repository: TokenRepositoryInterface,
                 jwt_service: JWTServiceInterface):
        """
        Initialize the refresh token use case.

        Args:
            user_repository: Repository for user data operations
            token_repository: Repository for token data operations
            jwt_service: Service for JWT token management
        """
        self.user_repository = user_repository
        self.token_repository = token_repository
        self.jwt_service = jwt_service

    async def execute(self, request: RefreshTokenRequest) -> RefreshTokenResponse:
        """
        Execute the token refresh use case.

        Args:
            request: Token refresh request containing refresh token

        Returns:
            RefreshTokenResponse: Result of the token refresh operation

        Raises:
            InvalidTokenException: If refresh token is invalid or malformed
            TokenExpiredException: If refresh token has expired
            TokenRevokedException: If refresh token has been revoked
            UserNotFoundException: If associated user doesn't exist
            UserInactiveException: If user account is inactive
        """
        refresh_token_claims = self.jwt_service.refresh_token_claims(request.refresh_token)
        user_id = self.jwt_service.extract_user_id(request.refresh_token)

        await self._validate_refresh_token(request.refresh_token)

        user = await self._validate_user_status(user_id)

        new_access_token = await self._generate_new_access_token(user_id, refresh_token_claims)

        return RefreshTokenResponse(
            success=True,
            access_token=new_access_token["token"],
            token_type="Bearer",
            expires_in=new_access_token["expires_in"]
        )

    async def _validate_refresh_token(self, refresh_token: str) -> None:
        """
        Validate the refresh token against stored tokens.

        Args:
            refresh_token: Refresh token string to validate

        Raises:
            TokenRevokedException: If token has been revoked
            InvalidTokenException: If token is not found in database
        """
        stored_token = await self.token_repository.find_by_token(refresh_token)

        if not stored_token:
            raise InvalidTokenException("Refresh token not found")

        if stored_token.is_revoked:
            raise TokenRevokedException()

        if not stored_token.is_valid():
            if stored_token.is_expired():
                raise TokenExpiredException()
            else:
                raise InvalidTokenException("Refresh token is invalid")

    async def _validate_user_status(self, user_id: str):
        """
        Validate that the user associated with the token is active.

        Args:
            user_id: User identifier from token

        Returns:
            User: Validated user entity

        Raises:
            UserNotFoundException: If user doesn't exist
            UserInactiveException: If user account is inactive
        """
        user = await self.user_repository.find_by_id(user_id)

        if not user:
            raise UserNotFoundException(user_id)

        if not user.is_active():
            raise UserInactiveException(user_id)

        return user

    async def _generate_new_access_token(self, user_id: str, claims: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a new access token for the user.

        Args:
            user_id: User identifier
            claims: Claims to include in the new token

        Returns:
            Dict[str, Any]: Dictionary containing new token and metadata
        """
        access_token_entity = AuthToken.create_access_token(user_id, expires_in_minutes=15)

        token_claims = self.jwt_service.create_token_claims(
            user_id,
            TokenType.ACCESS.value,
            claims
        )

        access_token_string = self.jwt_service.generate_token(
            access_token_entity,
            token_claims
        )

        access_token_entity.token = access_token_string
        await self.token_repository.create(access_token_entity)

        return {
            "token": access_token_string,
            "expires_in": 15 * 60
        }