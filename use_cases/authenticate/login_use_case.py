from dataclasses import dataclass
from typing import Dict, Any

from domain.entities.user import User
from domain.entities.auth_token import AuthToken, TokenType
from domain.exceptions import (
    InvalidCredentialsException,
    UserBlockedException,
    UserInactiveException
)
from interfaces.repositories.user_repository import UserRepositoryInterface
from interfaces.repositories.token_repository import TokenRepositoryInterface
from interfaces.services.password_service import PasswordServiceInterface
from interfaces.services.jwt_service import JWTServiceInterface


@dataclass
class LoginRequest:
    """
    Request data structure for user authentication use case.

    Contains the credentials provided by the user for authentication.

    Attributes:
        identifier: Email or username for authentication
        password: Plain text password
        remember_me: Whether to extend token expiration time
    """
    identifier: str
    password: str
    remember_me: bool = False


@dataclass
class LoginResponse:
    """
    Response data structure for user authentication use case.

    Contains the authentication result including tokens and user information.

    Attributes:
        success: Whether authentication was successful
        access_token: JWT access token for API access
        refresh_token: JWT refresh token for token renewal
        token_type: Type of token (typically "Bearer")
        expires_in: Access token expiration time in seconds
        user_data: Dictionary containing user information
    """
    success: bool
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user_data: Dict[str, Any]


class LoginUseCase:
    """
    Use case for handling user authentication operations.

    This use case encapsulates the business logic for authenticating users,
    including credential validation, token generation, and session management.

    It handles various authentication scenarios and ensures security requirements
    are met throughout the authentication process.
    """

    def __init__(self,
                 user_repository: UserRepositoryInterface,
                 token_repository: TokenRepositoryInterface,
                 password_service: PasswordServiceInterface,
                 jwt_service: JWTServiceInterface):
        """
        Initialize the authenticate user use case.

        Args:
            user_repository: Repository for user data operations
            token_repository: Repository for token data operations
            password_service: Service for password verification
            jwt_service: Service for JWT token management
        """
        self.user_repository = user_repository
        self.token_repository = token_repository
        self.password_service = password_service
        self.jwt_service = jwt_service

    async def execute(self, request: LoginRequest) -> LoginResponse:
        """
        Execute the user authentication use case.

        Args:
            request: Authentication request containing credentials

        Returns:
            LoginResponse: Result of the authentication operation

        Raises:
            InvalidCredentialsException: If credentials are invalid
            UserNotFoundException: If user doesn't exist
            UserBlockedException: If user account is blocked
            UserInactiveException: If user account is inactive
        """
        user = await self._find_user_by_identifier(request.identifier)

        if not user:
            raise InvalidCredentialsException()

        self._verify_password(request.password, user.password_hash)

        self._validate_user_status(user)

        await self._revoke_existing_tokens(user.id)

        tokens = await self._generate_token_pair(user, request.remember_me)

        await self._update_user_login(user)

        return LoginResponse(
            success=True,
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="Bearer",
            expires_in=tokens["expires_in"],
            user_data={
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "full_name": user.get_full_name(),
                "status": user.status.value,
                "last_login": user.last_login.isoformat() if user.last_login else None
            }
        )

    async def _find_user_by_identifier(self, identifier: str) -> User:
        """
        Find user by email or username identifier.

        Args:
            identifier: Email or username to search for

        Returns:
            User: Found user entity or None
        """
        user = await self.user_repository.find_by_email(identifier)
        if not user:
            user = await self.user_repository.find_by_username(identifier)
        return user

    def _verify_password(self, password: str, password_hash: str) -> None:
        """
        Verify the provided password against the stored hash.

        Args:
            password: Plain text password to verify
            password_hash: Stored password hash

        Raises:
            InvalidCredentialsException: If password verification fails
        """
        if not self.password_service.verify_password(password, password_hash):
            raise InvalidCredentialsException()

    def _validate_user_status(self, user: User) -> None:
        """
        Validate that the user account is in a valid state for authentication.

        Args:
            user: User entity to validate

        Raises:
            UserBlockedException: If user account is blocked
            UserInactiveException: If user account is inactive
        """
        if user.is_blocked():
            raise UserBlockedException(user.id)

        if not user.is_active():
            raise UserInactiveException(user.id)

    async def _revoke_existing_tokens(self, user_id: str) -> None:
        """
        Revoke all existing tokens for the user to ensure single session.

        Args:
            user_id: User identifier
        """
        await self.token_repository.revoke_all_user_tokens(user_id)

    async def _generate_token_pair(self, user: User, remember_me: bool) -> Dict[str, Any]:
        """
        Generate access and refresh token pair for the authenticated user.

        Args:
            user: Authenticated user entity
            remember_me: Whether to extend token expiration

        Returns:
            Dict[str, Any]: Dictionary containing generated tokens and metadata
        """
        access_expires_minutes = 30 if remember_me else 15
        refresh_expires_days = 90 if remember_me else 30

        access_token_entity = AuthToken.create_access_token(
            user.id,
            access_expires_minutes
        )
        refresh_token_entity = AuthToken.create_refresh_token(
            user.id,
            refresh_expires_days
        )

        access_claims = self.jwt_service.create_token_claims(
            user.id,
            TokenType.ACCESS.value,
            {
                "username": user.username,
                "email": user.email
            }
        )

        refresh_claims = self.jwt_service.create_token_claims(
            user.id,
            TokenType.REFRESH.value
        )

        access_token_string = self.jwt_service.generate_token(
            access_token_entity,
            access_claims
        )
        refresh_token_string = self.jwt_service.generate_token(
            refresh_token_entity,
            refresh_claims
        )

        access_token_entity.token = access_token_string
        refresh_token_entity.token = refresh_token_string

        await self.token_repository.create(access_token_entity)
        await self.token_repository.create(refresh_token_entity)

        return {
            "access_token": access_token_string,
            "refresh_token": refresh_token_string,
            "expires_in": access_expires_minutes * 60
        }

    async def _update_user_login(self, user: User) -> None:
        """
        Update user's last login timestamp.

        Args:
            user: User entity to update
        """
        user.update_last_login()
        await self.user_repository.update(user)