import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Email:
    """
    Email value object that ensures email format validation.

    This value object encapsulates email validation logic and provides
    a type-safe way to handle email addresses throughout the application.

    Attributes:
        value: The email address string
    """

    value: str

    def __post_init__(self):
        """
        Validate email format after initialization.

        Raises:
            ValueError: If email format is invalid
        """
        if not self._is_valid_email(self.value):
            raise ValueError(f"Invalid email format: {self.value}")

    def _is_valid_email(self, email: str) -> bool:
        """
        Validate email format using regex pattern.

        Args:
            email: Email string to validate

        Returns:
            bool: True if email format is valid, False otherwise
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def domain(self) -> str:
        """
        Extract domain part from email address.

        Returns:
            str: Domain part of the email
        """
        return self.value.split('@')[1]

    def local_part(self) -> str:
        """
        Extract local part from email address.

        Returns:
            str: Local part of the email (before @)
        """
        return self.value.split('@')[0]


@dataclass(frozen=True)
class Username:
    """
    Username value object that ensures username format validation.

    This value object encapsulates username validation rules and provides
    a type-safe way to handle usernames throughout the application.

    Attributes:
        value: The username string
    """

    value: str
    MIN_LENGTH = 3
    MAX_LENGTH = 30

    def __post_init__(self):
        """
        Validate username format after initialization.

        Raises:
            ValueError: If username format is invalid
        """
        if not self._is_valid_username(self.value):
            raise ValueError(f"Invalid username format: {self.value}")

    def _is_valid_username(self, username: str) -> bool:
        """
        Validate username format and length.

        Args:
            username: Username string to validate

        Returns:
            bool: True if username format is valid, False otherwise
        """
        if len(username) < self.MIN_LENGTH or len(username) > self.MAX_LENGTH:
            return False

        pattern = r'^[a-zA-Z0-9_-]+$'
        return re.match(pattern, username) is not None

    def to_lowercase(self) -> str:
        """
        Convert username to lowercase for case-insensitive operations.

        Returns:
            str: Lowercase username
        """
        return self.value.lower()


@dataclass(frozen=True)
class Password:
    """
    Password value object that ensures password strength validation.

    This value object encapsulates password validation rules and provides
    methods for password strength checking.

    Attributes:
        value: The plain text password string
    """

    value: str
    MIN_LENGTH = 8
    MAX_LENGTH = 128

    def __post_init__(self):
        """
        Validate password strength after initialization.

        Raises:
            ValueError: If password doesn't meet requirements
        """
        if not self._is_valid_password(self.value):
            raise ValueError("Password doesn't meet security requirements")

    def _is_valid_password(self, password: str) -> bool:
        """
        Validate password strength requirements.

        Args:
            password: Password string to validate

        Returns:
            bool: True if password meets requirements, False otherwise
        """
        if len(password) < self.MIN_LENGTH or len(password) > self.MAX_LENGTH:
            return False

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        return has_upper and has_lower and has_digit and has_special

    def strength_score(self) -> int:
        """
        Calculate password strength score from 0 to 100.

        Returns:
            int: Password strength score
        """
        score = 0
        password = self.value

        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if any(c.isupper() for c in password):
            score += 20
        if any(c.islower() for c in password):
            score += 20
        if any(c.isdigit() for c in password):
            score += 15
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 15

        return min(score, 100)