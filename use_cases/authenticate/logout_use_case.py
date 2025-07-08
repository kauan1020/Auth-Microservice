from dataclasses import dataclass

from domain.exceptions import InvalidTokenException
from interfaces.repositories.token_repository import TokenRepositoryInterface
from interfaces.services.jwt_service import JWTServiceInterface


@dataclass
class LogoutRequest:
    """
    Request data structure for user logout use case.

    Contains the access token that should be invalidated
    during the logout process.

    Attributes:
        access_token: JWT access token to be revoked
        revoke_all: Whether to revoke all user tokens or just the current one
    """
    access_token: str
    revoke_all: bool = False


@dataclass
class LogoutResponse:
    """
    Response data structure for user logout use case.

    Contains the result of the logout operation including
    the number of tokens revoked and operation status.

    Attributes:
        success: Whether logout was successful
        message: Status message
        tokens_revoked: Number of tokens revoked during logout
    """
    success: bool
    message: str
    tokens_revoked: int


class LogoutUseCase:
    """
    Use case for handling user logout operations.

    This use case encapsulates the business logic for user logout,
    including token revocation, session cleanup, and security measures
    to ensure proper termination of user sessions.

    It provides options for revoking single tokens or all user tokens
    depending on the security requirements and user preferences.
    """

    def __init__(self,
                 token_repository: TokenRepositoryInterface,
                 jwt_service: JWTServiceInterface):
        """
        Initialize the logout use case.

        Args:
            token_repository: Repository for token data operations
            jwt_service: Service for JWT token management
        """
        self.token_repository = token_repository
        self.jwt_service = jwt_service

    async def execute(self, request: LogoutRequest) -> LogoutResponse:
        """
        Execute the user logout use case.

        Args:
            request: Logout request containing token information

        Returns:
            LogoutResponse: Result of the logout operation

        Raises:
            InvalidTokenException: If provided token is invalid
        """
        user_id = await self._extract_user_from_token(request.access_token)

        tokens_revoked = await self._revoke_tokens(user_id, request.access_token, request.revoke_all)

        message = self._create_logout_message(tokens_revoked, request.revoke_all)

        return LogoutResponse(
            success=True,
            message=message,
            tokens_revoked=tokens_revoked
        )

    async def _extract_user_from_token(self, access_token: str) -> str:
        """
        Extract user ID from the provided access token.

        Args:
            access_token: JWT access token

        Returns:
            str: User ID extracted from token

        Raises:
            InvalidTokenException: If token is invalid or expired
        """
        try:
            return self.jwt_service.extract_user_id(access_token)
        except Exception as e:
            raise InvalidTokenException(f"Invalid access token: {str(e)}")

    async def _revoke_tokens(self, user_id: str, access_token: str, revoke_all: bool) -> int:
        """
        Revoke user tokens based on logout strategy.

        Args:
            user_id: User identifier
            access_token: Current access token
            revoke_all: Whether to revoke all tokens or just current one

        Returns:
            int: Number of tokens revoked
        """
        if revoke_all:
            return await self.token_repository.revoke_all_user_tokens(user_id)
        else:
            current_revoked = await self.token_repository.revoke_token(access_token)
            return 1 if current_revoked else 0

    def _create_logout_message(self, tokens_revoked: int, revoke_all: bool) -> str:
        """
        Create appropriate logout message based on operation result.

        Args:
            tokens_revoked: Number of tokens that were revoked
            revoke_all: Whether all tokens were targeted for revocation

        Returns:
            str: Logout status message
        """
        if revoke_all:
            if tokens_revoked > 0:
                return f"Successfully logged out from all devices. {tokens_revoked} sessions terminated."
            else:
                return "Successfully logged out. No active sessions found."
        else:
            if tokens_revoked > 0:
                return "Successfully logged out from current session."
            else:
                return "Logout completed. Session was already terminated."