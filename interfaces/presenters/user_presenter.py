from abc import ABC, abstractmethod
from typing import Any, Dict

class UserPresenterInterface(ABC):
    """
    Interface for user data presentation.

    Defines the contract for formatting user-related responses
    according to API specifications and client requirements.
    """

    @abstractmethod
    def present_user_profile(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format user profile response."""
        pass

    @abstractmethod
    def present_profile_update_success(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format successful profile update response."""
        pass

    @abstractmethod
    def present_password_change_success(self) -> Dict[str, Any]:
        """Format successful password change response."""
        pass

    @abstractmethod
    def present_user_not_found(self) -> Dict[str, Any]:
        """Format user not found error response."""
        pass
