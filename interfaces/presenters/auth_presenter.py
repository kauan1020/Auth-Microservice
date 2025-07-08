from abc import ABC, abstractmethod
from typing import Any, Dict

class AuthPresenterInterface(ABC):
    """
    Interface for authentication response presentation.

    Defines the contract for formatting authentication responses
    according to API specifications and client requirements.
    """

    @abstractmethod
    def present_registration_success(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format successful registration response."""
        pass

    @abstractmethod
    def present_login_success(self, auth_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format successful login response."""
        pass

    @abstractmethod
    def present_logout_success(self) -> Dict[str, Any]:
        """Format successful logout response."""
        pass

    @abstractmethod
    def present_token_refresh_success(self, token_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format successful token refresh response."""
        pass

    @abstractmethod
    def present_validation_error(self, errors: Dict[str, Any]) -> Dict[str, Any]:
        """Format validation error response."""
        pass

    @abstractmethod
    def present_authentication_error(self, message: str) -> Dict[str, Any]:
        """Format authentication error response."""
        pass