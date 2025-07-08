from abc import ABC, abstractmethod
from typing import Optional, List
from domain.entities.auth_token import AuthToken, TokenType


class TokenRepositoryInterface(ABC):
    """
    Repository interface for AuthToken entity operations.

    This interface defines the contract for token data persistence operations,
    managing JWT tokens lifecycle including creation, validation, and revocation.

    The implementation should handle token storage, retrieval, and cleanup
    operations while maintaining security and performance requirements.
    """

    @abstractmethod
    async def create(self, token: AuthToken) -> AuthToken:
        """
        Store a new token in the repository.

        Args:
            token: AuthToken entity to be stored

        Returns:
            AuthToken: Stored token with any generated fields
        """
        pass

    @abstractmethod
    async def find_by_token(self, token_string: str) -> Optional[AuthToken]:
        """
        Find a token by its string value.

        Args:
            token_string: JWT token string to search for

        Returns:
            Optional[AuthToken]: Token entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_user_id(self, user_id: str, token_type: TokenType) -> List[AuthToken]:
        """
        Find all tokens for a specific user and token type.

        Args:
            user_id: User identifier
            token_type: Type of tokens to retrieve

        Returns:
            List[AuthToken]: List of tokens matching the criteria
        """
        pass

    @abstractmethod
    async def find_active_tokens_by_user(self, user_id: str) -> List[AuthToken]:
        """
        Find all active (non-expired, non-revoked) tokens for a user.

        Args:
            user_id: User identifier

        Returns:
            List[AuthToken]: List of active tokens for the user
        """
        pass

    @abstractmethod
    async def revoke_token(self, token_string: str) -> bool:
        """
        Revoke a specific token by marking it as revoked.

        Args:
            token_string: JWT token string to revoke

        Returns:
            bool: True if token was successfully revoked, False otherwise
        """
        pass

    @abstractmethod
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a specific user.

        Args:
            user_id: User identifier

        Returns:
            int: Number of tokens revoked
        """
        pass

    @abstractmethod
    async def revoke_user_tokens_by_type(self, user_id: str, token_type: TokenType) -> int:
        """
        Revoke all tokens of a specific type for a user.

        Args:
            user_id: User identifier
            token_type: Type of tokens to revoke

        Returns:
            int: Number of tokens revoked
        """
        pass

    @abstractmethod
    async def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from the repository.

        This method should be called periodically to maintain repository
        performance and remove tokens that are no longer valid.

        Returns:
            int: Number of expired tokens removed
        """
        pass

    @abstractmethod
    async def is_token_revoked(self, token_string: str) -> bool:
        """
        Check if a token has been revoked.

        Args:
            token_string: JWT token string to check

        Returns:
            bool: True if token is revoked, False otherwise
        """
        pass

    @abstractmethod
    async def update_token(self, token: AuthToken) -> AuthToken:
        """
        Update an existing token in the repository.

        Args:
            token: AuthToken entity with updated information

        Returns:
            AuthToken: Updated token entity
        """
        pass