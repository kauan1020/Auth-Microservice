from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime

from domain.entities.user import User
from domain.exceptions import UserNotFoundException, UserAlreadyExistsException
from interfaces.repositories.user_repository import UserRepositoryInterface


@dataclass
class UpdateUserRequest:
    """
    Request data structure for updating user information.

    Contains the user identifier and fields to be updated.

    Attributes:
        user_id: Unique identifier of the user
        first_name: Optional new first name
        last_name: Optional new last name
        username: Optional new username
    """
    user_id: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None


@dataclass
class UpdateUserResponse:
    """
    Response data structure for user update operations.

    Contains the updated user data and operation status.

    Attributes:
        success: Whether the update was successful
        message: Status message
        user_data: Dictionary containing updated user information
    """
    success: bool
    message: str
    user_data: Dict[str, Any]


class UpdateUserUseCase:
    """
    Use case for updating user profile information.

    This use case encapsulates the business logic for updating user data,
    including validation, uniqueness checks, and proper error handling.
    """

    def __init__(self, user_repository: UserRepositoryInterface):
        """
        Initialize the update user use case.

        Args:
            user_repository: Repository for user data operations
        """
        self.user_repository = user_repository

    async def execute(self, request: UpdateUserRequest) -> UpdateUserResponse:
        """
        Execute the update user use case.

        Args:
            request: Update user request containing user ID and updated fields

        Returns:
            UpdateUserResponse: Updated user information and operation status

        Raises:
            UserNotFoundException: If user doesn't exist
            UserAlreadyExistsException: If username is already taken
        """
        user = await self._get_user(request.user_id)

        if request.username and request.username != user.username:
            await self._validate_username_uniqueness(request.username, user.id)

        updated_user = await self._update_user_fields(user, request)

        return UpdateUserResponse(
            success=True,
            message="User profile updated successfully",
            user_data={
                "id": updated_user.id,
                "email": updated_user.email,
                "username": updated_user.username,
                "first_name": updated_user.first_name,
                "last_name": updated_user.last_name,
                "full_name": updated_user.get_full_name(),
                "status": updated_user.status.value,
                "updated_at": updated_user.updated_at.isoformat() if updated_user.updated_at else None
            }
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

    async def _validate_username_uniqueness(self, username: str, current_user_id: str) -> None:
        """
        Validate that the new username is not already taken.

        Args:
            username: New username to validate
            current_user_id: Current user ID to exclude from check

        Raises:
            UserAlreadyExistsException: If username is already taken
        """
        existing_user = await self.user_repository.find_by_username(username)
        if existing_user and existing_user.id != current_user_id:
            raise UserAlreadyExistsException("username", username)

    async def _update_user_fields(self, user: User, request: UpdateUserRequest) -> User:
        """
        Update user fields based on the request data.

        Args:
            user: User entity to update
            request: Update request with new field values

        Returns:
            User: Updated user entity
        """
        if request.first_name is not None:
            user.first_name = request.first_name.strip()

        if request.last_name is not None:
            user.last_name = request.last_name.strip()

        if request.username is not None:
            user.username = request.username.strip()

        user.updated_at = datetime.utcnow()

        return await self.user_repository.update(user)