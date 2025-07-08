from dataclasses import dataclass

from interfaces.repositories.token_repository import TokenRepositoryInterface
from interfaces.services.jwt_service import JWTServiceInterface


@dataclass
class ValidateTokenRequest:
    """
    Request data structure for token validation use case.

    Contains the token that needs to be validated.

    Attributes:
        token: JWT token string to validate
    """
    token: str


@dataclass
class ValidateTokenResponse:
    """
    Response data structure for token validation use case.

    Contains the validation result and token information.

    Attributes:
        valid: Whether the token is valid
        user_id: User ID extracted from token (if valid)
        token_type: Type of token (access or refresh)
        expires_at: Token expiration timestamp
        issued_at: Token issuance timestamp
        reason: Reason for validation failure (if invalid)
    """
    valid: bool
    user_id: str = None
    token_type: str = None
    expires_at: int = None
    issued_at: int = None
    reason: str = None


class ValidateTokenUseCase:
    """
    Use case for handling token validation operations.

    This use case encapsulates the business logic for validating JWT tokens,
    including signature verification, expiration checking, and database validation
    to ensure tokens are still valid and not revoked.
    """

    def __init__(self,
                 token_repository: TokenRepositoryInterface,
                 jwt_service: JWTServiceInterface):
        """
        Initialize the token validation use case.

        Args:
            token_repository: Repository for token data operations
            jwt_service: Service for JWT token management
        """
        self.token_repository = token_repository
        self.jwt_service = jwt_service

    async def execute(self, request: ValidateTokenRequest) -> ValidateTokenResponse:
        """
        Execute token validation.

        Args:
            request: Token validation request containing token to validate

        Returns:
            ValidateTokenResponse: Validation result with token information
        """
        try:
            claims = self.jwt_service.decode_token(request.token)

            is_revoked = await self.token_repository.is_token_revoked(request.token)

            if is_revoked:
                return ValidateTokenResponse(
                    valid=False,
                    reason="Token has been revoked"
                )

            return ValidateTokenResponse(
                valid=True,
                user_id=claims.get("sub"),
                token_type=claims.get("type"),
                expires_at=claims.get("exp"),
                issued_at=claims.get("iat")
            )

        except Exception as e:
            return ValidateTokenResponse(
                valid=False,
                reason=str(e)
            )