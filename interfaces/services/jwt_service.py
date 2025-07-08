from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from domain.entities.auth_token import AuthToken


class JWTServiceInterface(ABC):
    """
    Service interface for JWT token management operations.

    This interface defines the contract for JWT token creation, validation,
    and management operations used throughout the authentication system.

    The implementation should handle token encoding/decoding, signature
    validation, and claim management securely.
    """

    @abstractmethod
    def generate_token(self, token: AuthToken, claims: Dict[str, Any]) -> str:
        """
        Generate a JWT token string from an AuthToken entity and claims.

        Args:
            token: AuthToken entity containing token metadata
            claims: Dictionary of claims to include in the JWT payload

        Returns:
            str: Generated JWT token string
        """
        pass

    @abstractmethod
    def decode_token(self, token_string: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token string.

        Args:
            token_string: JWT token string to decode

        Returns:
            Dict[str, Any]: Dictionary containing token claims

        Raises:
            InvalidTokenException: If token is malformed or invalid
            TokenExpiredException: If token has expired
        """
        pass

    @abstractmethod
    def extract_user_id(self, token_string: str) -> str:
        """
        Extract user ID from a JWT token.

        Args:
            token_string: JWT token string

        Returns:
            str: User ID extracted from token claims

        Raises:
            InvalidTokenException: If token is invalid or missing user ID
        """
        pass

    @abstractmethod
    def extract_token_type(self, token_string: str) -> str:
        """
        Extract token type from a JWT token.

        Args:
            token_string: JWT token string

        Returns:
            str: Token type (access or refresh)

        Raises:
            InvalidTokenException: If token is invalid or missing token type
        """
        pass

    @abstractmethod
    def is_token_expired(self, token_string: str) -> bool:
        """
        Check if a JWT token has expired.

        Args:
            token_string: JWT token string to check

        Returns:
            bool: True if token is expired, False otherwise
        """
        pass

    @abstractmethod
    def get_token_expiration(self, token_string: str) -> Optional[int]:
        """
        Get the expiration timestamp from a JWT token.

        Args:
            token_string: JWT token string

        Returns:
            Optional[int]: Unix timestamp of token expiration, None if not found
        """
        pass

    @abstractmethod
    def refresh_token_claims(self, refresh_token: str) -> Dict[str, Any]:
        """
        Extract claims from a refresh token for generating new access token.

        Args:
            refresh_token: Refresh token string

        Returns:
            Dict[str, Any]: Dictionary containing claims for new access token

        Raises:
            InvalidTokenException: If refresh token is invalid
            TokenExpiredException: If refresh token has expired
        """
        pass

    @abstractmethod
    def create_token_claims(self, user_id: str, token_type: str,
                            additional_claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create standardized claims dictionary for JWT token generation.

        Args:
            user_id: User identifier
            token_type: Type of token (access or refresh)
            additional_claims: Optional additional claims to include

        Returns:
            Dict[str, Any]: Dictionary containing standardized JWT claims
        """
        pass
