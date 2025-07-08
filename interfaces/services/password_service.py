from abc import ABC, abstractmethod


class PasswordServiceInterface(ABC):
    """
    Service interface for password management operations.

    This interface defines the contract for password-related operations
    including hashing, verification, and security validations.

    The implementation should use secure hashing algorithms and follow
    best practices for password security management.
    """

    @abstractmethod
    def hash_password(self, password: str) -> str:
        """
        Hash a plain text password using a secure algorithm.

        Args:
            password: Plain text password to hash

        Returns:
            str: Hashed password string
        """
        pass

    @abstractmethod
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a plain text password against its hash.

        Args:
            password: Plain text password to verify
            hashed_password: Previously hashed password to compare against

        Returns:
            bool: True if password matches the hash, False otherwise
        """
        pass

    @abstractmethod
    def is_password_compromised(self, password: str) -> bool:
        """
        Check if a password has been compromised in known data breaches.

        This method can integrate with services like HaveIBeenPwned to check
        if the password appears in known breach databases.

        Args:
            password: Plain text password to check

        Returns:
            bool: True if password is compromised, False otherwise
        """
        pass

    @abstractmethod
    def generate_secure_password(self, length: int = 12) -> str:
        """
        Generate a cryptographically secure random password.

        Args:
            length: Desired password length (minimum 8 characters)

        Returns:
            str: Generated secure password
        """
        pass

    @abstractmethod
    def validate_password_strength(self, password: str) -> dict:
        """
        Validate password strength and return detailed feedback.

        Args:
            password: Plain text password to validate

        Returns:
            dict: Dictionary containing validation results with keys:
                - is_valid: bool indicating if password meets requirements
                - score: int from 0-100 indicating password strength
                - feedback: list of strings with improvement suggestions
        """
        pass