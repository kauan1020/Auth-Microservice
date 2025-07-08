from dataclasses import dataclass
from datetime import datetime

from domain.entities.user import User
from domain.value_objects import Password
from domain.exceptions import (
    UserNotFoundException,
    InvalidCredentialsException,
    WeakPasswordException
)
from interfaces.repositories.user_repository import UserRepositoryInterface
from interfaces.services.password_service import PasswordServiceInterface


@dataclass
class ChangePasswordRequest:
    """
    Request data structure for password change operations.

    Contains the user identifier and password information.

    Attributes:
        user_id: Unique identifier of the user
        current_password: Current password for verification
        new_password: New password to set
    """
    user_id: str
    current_password: str
    new_password: str


@dataclass
class ChangePasswordResponse:
    """
    Response data structure for password change operations.

    Contains the operation result and status information.

    Attributes:
        success: Whether the password change was successful
        message: Status message
    """
    success: bool
    message: str


class ChangePasswordUseCase:
    """
    Use case for changing user password.

    This use case encapsulates the business logic for password changes,
    including current password verification, new password validation,
    and secure password hashing.
    """

    def __init__(self,
                 user_repository: UserRepositoryInterface,
                 password_service: PasswordServiceInterface):
        """
        Initialize the change password use case.

        Args:
            user_repository: Repository for user data operations
            password_service: Service for password management
        """
        self.user_repository = user_repository
        self.password_service = password_service

    async def execute(self, request: ChangePasswordRequest) -> ChangePasswordResponse:
        """
        Execute the change password use case.

        Args:
            request: Change password request containing user ID and passwords

        Returns:
            ChangePasswordResponse: Password change operation status

        Raises:
            UserNotFoundException: If user doesn't exist
            InvalidCredentialsException: If current password is incorrect
            WeakPasswordException: If new password doesn't meet requirements
        """
        user = await self._get_user(request.user_id)

        self._verify_current_password(request.current_password, user.password_hash)

        self._validate_new_password(request.new_password)

        await self._update_user_password(user, request.new_password)

        return ChangePasswordResponse(
            success=True,
            message="Password changed successfully"
        )

    async def _get_user(self, user_id: str) -> User:
        """
        Retrieve user by ID with proper error handling.

        Args:
            user_id: User identifier

        Returns:
            User: User entity

        Raises:
            UserNotFoundException: If user doesn't exist
        """
        user = await self.user_repository.find_by_id(user_id)
        if not user:
            raise UserNotFoundException(user_id)
        return user

    def _verify_current_password(self, current_password: str, stored_hash: str) -> None:
        """
        Verify the current password against the stored hash.

        Args:
            current_password: Current password provided by user
            stored_hash: Stored password hash

        Raises:
            InvalidCredentialsException: If current password is incorrect
        """
        if not self.password_service.verify_password(current_password, stored_hash):
            raise InvalidCredentialsException()

    def _validate_new_password(self, new_password: str) -> None:
        """
        Validate the new password meets security requirements.

        Args:
            new_password: New password to validate

        Raises:
            WeakPasswordException: If password doesn't meet requirements
        """
        try:
            Password(new_password)
        except ValueError as e:
            raise WeakPasswordException(str(e))

        validation_result = self.password_service.validate_password_strength(new_password)
        if not validation_result["is_valid"]:
            feedback = ", ".join(validation_result["feedback"])
            raise WeakPasswordException(feedback)

        if self.password_service.is_password_compromised(new_password):
            raise WeakPasswordException("Password has been compromised in data breaches")

    async def _update_user_password(self, user: User, new_password: str) -> None:
        """
        Update user password with new hashed password.

        Args:
            user: User entity to update
            new_password: New password to hash and store
        """
        user.password_hash = self.password_service.hash_password(new_password)
        user.updated_at = datetime.utcnow()

        await self.user_repository.update(user)