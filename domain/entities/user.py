from datetime import datetime
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class UserStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BLOCKED = "blocked"


@dataclass
class User:
    """
    User entity representing a system user with authentication capabilities.

    This entity encapsulates all user-related business logic and maintains
    the core attributes required for user management and authentication.

    Attributes:
        id: Unique identifier for the user
        email: User's email address (used for authentication)
        username: User's chosen username
        password_hash: Hashed password for security
        first_name: User's first name
        last_name: User's last name
        status: Current user status (active, inactive, blocked)
        created_at: Timestamp when the user was created
        updated_at: Timestamp when the user was last updated
        last_login: Timestamp of the user's last login
    """

    id: Optional[str]
    email: str
    username: str
    password_hash: str
    first_name: str
    last_name: str
    status: UserStatus
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    last_login: Optional[datetime]

    def is_active(self) -> bool:
        """
        Check if the user is in active status.

        Returns:
            bool: True if user status is active, False otherwise
        """
        return self.status == UserStatus.ACTIVE

    def is_blocked(self) -> bool:
        """
        Check if the user is blocked.

        Returns:
            bool: True if user status is blocked, False otherwise
        """
        return self.status == UserStatus.BLOCKED

    def get_full_name(self) -> str:
        """
        Get the user's full name by combining first and last name.

        Returns:
            str: Full name of the user
        """
        return f"{self.first_name} {self.last_name}".strip()

    def update_last_login(self) -> None:
        """
        Update the last login timestamp to current time.
        """
        self.last_login = datetime.utcnow()
        self.updated_at = datetime.utcnow()