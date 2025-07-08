from abc import ABC, abstractmethod
from fastapi import Request, Response


class AuthControllerInterface(ABC):
    """
    Interface for authentication controller operations.

    Defines the contract for HTTP request handling in the authentication
    context, including user registration, login, logout, and token operations.
    """

    @abstractmethod
    async def register(self, request: Request) -> Response:
        """Handle user registration HTTP request."""
        pass

    @abstractmethod
    async def login(self, request: Request) -> Response:
        """Handle user login HTTP request."""
        pass

    @abstractmethod
    async def logout(self, request: Request) -> Response:
        """Handle user logout HTTP request."""
        pass

    @abstractmethod
    async def refresh_token(self, request: Request) -> Response:
        """Handle token refresh HTTP request."""
        pass

    @abstractmethod
    async def validate_token(self, request: Request) -> Response:
        """Handle token validation HTTP request."""
        pass
