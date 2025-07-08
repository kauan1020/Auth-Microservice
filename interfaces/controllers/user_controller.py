from abc import ABC, abstractmethod
from fastapi import Request, Response

class UserControllerInterface(ABC):
    """
    Interface for user management controller operations.

    Defines the contract for HTTP request handling in user management
    context, including user CRUD operations and profile management.
    """

    @abstractmethod
    async def get_user_profile(self, request: Request) -> Response:
        """Get user profile information."""
        pass

    @abstractmethod
    async def update_user_profile(self, request: Request) -> Response:
        """Update user profile information."""
        pass

    @abstractmethod
    async def change_password(self, request: Request) -> Response:
        """Handle password change request."""
        pass

    @abstractmethod
    async def deactivate_user(self, request: Request) -> Response:
        """Handle user deactivation request."""
        pass
