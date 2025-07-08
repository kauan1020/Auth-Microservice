from dataclasses import dataclass
from typing import Dict, Any

from domain.exceptions import UserNotFoundException
from interfaces.repositories.user_repository import UserRepositoryInterface


@dataclass
class GetUserRequest:
    """
    Request data structure for getting user information.

    Contains the user identifier for retrieving user data.

    Attributes:
        user_id: Unique identifier of the user
    """
    user_id: str


@dataclass
class GetUserResponse:
    """
    Response data structure for user information retrieval.

    Contains the user data and operation status.

    Attributes:
        success: Whether the operation was successful
        user_data: Dictionary containing user information
    """
    success: bool
    user_data: Dict[str, Any]


class GetUserUseCase:
    """
    Use case for retrieving user information.

    This use case encapsulates the business logic for fetching user data
    by user ID, including proper error handling for non-existent users.
    """

    def __init__(self, user_repository: UserRepositoryInterface):
        """
        Initialize the get user use case.

        Args:
            user_repository: Repository for user data operations
        """
        self.user_repository = user_repository

    async def execute(self, request: GetUserRequest) -> GetUserResponse:
        """
        Execute the get user use case.

        Args:
            request: Get user request containing user ID

        Returns:
            GetUserResponse: User information and operation status

        Raises:
            UserNotFoundException: If user doesn't exist
        """
        user = await self.user_repository.find_by_id(request.user_id)

        if not user:
            raise UserNotFoundException(request.user_id)

        return GetUserResponse(
            success=True,
            user_data={
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "full_name": user.get_full_name(),
                "status": user.status.value,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None
            }
        )