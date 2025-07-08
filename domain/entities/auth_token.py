from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass
class AuthToken:
    """
    Authentication token entity for managing JWT tokens and session handling.

    This entity represents both access and refresh tokens used in the authentication
    system, providing methods to validate token expiration and manage token lifecycle.

    Attributes:
        token: The JWT token string
        token_type: Type of token (access or refresh)
        user_id: ID of the user associated with this token
        expires_at: Timestamp when the token expires
        created_at: Timestamp when the token was created
        is_revoked: Flag indicating if the token has been revoked
    """

    token: str
    token_type: TokenType
    user_id: str
    expires_at: datetime
    created_at: Optional[datetime]
    is_revoked: bool = False

    def is_expired(self) -> bool:
        """
        Check if the token has expired.

        Returns:
            bool: True if token is expired, False otherwise
        """
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """
        Check if the token is valid (not expired and not revoked).

        Returns:
            bool: True if token is valid, False otherwise
        """
        return not self.is_expired() and not self.is_revoked

    def revoke(self) -> None:
        """
        Revoke the token, making it invalid for future use.
        """
        self.is_revoked = True

    def time_until_expiry(self) -> timedelta:
        """
        Calculate the time remaining until token expiration.

        Returns:
            timedelta: Time remaining until expiration
        """
        return self.expires_at - datetime.utcnow()

    @classmethod
    def create_access_token(cls, user_id: str, expires_in_minutes: int = 15) -> 'AuthToken':
        """
        Create a new access token for the given user.

        Args:
            user_id: ID of the user
            expires_in_minutes: Token expiration time in minutes

        Returns:
            AuthToken: New access token instance
        """
        return cls(
            token="",
            token_type=TokenType.ACCESS,
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(minutes=expires_in_minutes),
            created_at=datetime.utcnow()
        )

    @classmethod
    def create_refresh_token(cls, user_id: str, expires_in_days: int = 30) -> 'AuthToken':
        """
        Create a new refresh token for the given user.

        Args:
            user_id: ID of the user
            expires_in_days: Token expiration time in days

        Returns:
            AuthToken: New refresh token instance
        """
        return cls(
            token="",
            token_type=TokenType.REFRESH,
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(days=expires_in_days),
            created_at=datetime.utcnow()
        )