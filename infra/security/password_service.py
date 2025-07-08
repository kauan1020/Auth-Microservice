import bcrypt
import secrets
import string
import hashlib
import httpx
from typing import Dict, List

from interfaces.services.password_service import PasswordServiceInterface


class PasswordService(PasswordServiceInterface):
    """
    Implementation of password management operations using bcrypt.

    This service provides secure password hashing, verification, and validation
    using industry-standard bcrypt algorithm with configurable work factors.

    It includes password strength validation, compromise checking via
    HaveIBeenPwned API, and secure password generation capabilities.
    """

    def __init__(self, rounds: int = 12, check_compromised: bool = True):
        """
        Initialize password service with configuration options.

        Args:
            rounds: bcrypt work factor (4-31, higher is more secure but slower)
            check_compromised: Whether to check passwords against breach databases
        """
        self.rounds = max(4, min(31, rounds))
        self.check_compromised = check_compromised
        self._min_length = 8
        self._max_length = 128

    def hash_password(self, password: str) -> str:
        """
        Hash a plain text password using bcrypt with salt.

        Args:
            password: Plain text password to hash

        Returns:
            str: Bcrypt hashed password string
        """
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a plain text password against its bcrypt hash.

        Args:
            password: Plain text password to verify
            hashed_password: Previously hashed password to compare against

        Returns:
            bool: True if password matches the hash, False otherwise
        """
        try:
            password_bytes = password.encode('utf-8')
            hashed_bytes = hashed_password.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except (ValueError, TypeError):
            return False

    def is_password_compromised(self, password: str) -> bool:
        """
        Check if a password has been compromised using HaveIBeenPwned API.

        This method implements k-anonymity by sending only the first 5 characters
        of the SHA-1 hash to the API, preserving password privacy.

        Args:
            password: Plain text password to check

        Returns:
            bool: True if password is compromised, False otherwise
        """
        if not self.check_compromised:
            return False

        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            url = f"https://api.pwnedpasswords.com/range/{prefix}"

            with httpx.Client(timeout=5.0) as client:
                response = client.get(url)
                response.raise_for_status()

                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count) > 0

                return False

        except Exception:
            return False

    def generate_secure_password(self, length: int = 12) -> str:
        """
        Generate a cryptographically secure random password.

        Creates a password with mixed case letters, digits, and special characters
        ensuring good entropy and meeting common password requirements.

        Args:
            length: Desired password length (minimum 8 characters)

        Returns:
            str: Generated secure password
        """
        if length < 8:
            length = 8
        if length > 128:
            length = 128

        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def validate_password_strength(self, password: str) -> Dict[str, any]:
        """
        Validate password strength and return detailed feedback.

        Checks password against multiple criteria including length, character
        diversity, common patterns, and provides actionable feedback.

        Args:
            password: Plain text password to validate

        Returns:
            dict: Dictionary containing validation results with keys:
                - is_valid: bool indicating if password meets requirements
                - score: int from 0-100 indicating password strength
                - feedback: list of strings with improvement suggestions
        """
        feedback = []
        score = 0

        length = len(password)
        if length < self._min_length:
            feedback.append(f"Password must be at least {self._min_length} characters long")
        elif length >= self._min_length:
            score += 20
            if length >= 12:
                score += 10
            if length >= 16:
                score += 10

        if length > self._max_length:
            feedback.append(f"Password must not exceed {self._max_length} characters")
            return {"is_valid": False, "score": 0, "feedback": feedback}

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if has_lower:
            score += 15
        else:
            feedback.append("Add lowercase letters")

        if has_upper:
            score += 15
        else:
            feedback.append("Add uppercase letters")

        if has_digit:
            score += 15
        else:
            feedback.append("Add numbers")

        if has_special:
            score += 15
        else:
            feedback.append("Add special characters (!@#$%^&*)")

        if self._has_repeated_characters(password):
            score -= 10
            feedback.append("Avoid repeated characters")

        if self._has_sequential_characters(password):
            score -= 10
            feedback.append("Avoid sequential characters (abc, 123)")

        if self._is_common_pattern(password):
            score -= 20
            feedback.append("Avoid common patterns and dictionary words")

        score = max(0, min(100, score))
        is_valid = score >= 60 and length >= self._min_length and length <= self._max_length

        if not feedback and is_valid:
            feedback.append("Strong password")

        return {
            "is_valid": is_valid,
            "score": score,
            "feedback": feedback
        }

    def _has_repeated_characters(self, password: str, max_repeat: int = 2) -> bool:
        """
        Check if password has too many repeated characters.

        Args:
            password: Password to check
            max_repeat: Maximum allowed consecutive repeated characters

        Returns:
            bool: True if password has excessive repeated characters
        """
        for i in range(len(password) - max_repeat):
            if password[i] == password[i + 1] == password[i + 2]:
                return True
        return False

    def _has_sequential_characters(self, password: str) -> bool:
        """
        Check if password contains sequential characters.

        Args:
            password: Password to check

        Returns:
            bool: True if password contains sequential patterns
        """
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ]

        password_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i + 3] in password_lower or seq[i:i + 3][::-1] in password_lower:
                    return True
        return False

    def _is_common_pattern(self, password: str) -> bool:
        """
        Check if password follows common patterns.

        Args:
            password: Password to check

        Returns:
            bool: True if password follows common patterns
        """
        common_patterns = [
            "password", "123456", "qwerty", "admin", "login",
            "welcome", "monkey", "dragon", "master", "shadow"
        ]

        password_lower = password.lower()
        for pattern in common_patterns:
            if pattern in password_lower:
                return True
        return False