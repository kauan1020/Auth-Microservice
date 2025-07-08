from typing import Dict, Any, List
from datetime import datetime

from interfaces.presenters.auth_presenter import AuthPresenterInterface


class AuthPresenter(AuthPresenterInterface):
    """
    Implementation of authentication response presentation.

    This presenter formats authentication responses according to API specifications,
    ensuring consistent response structure and proper data serialization for clients.

    It handles success responses, error formatting, and data transformation
    to maintain a clean separation between business logic and presentation concerns.
    """

    def present_registration_success(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format successful registration response.

        Args:
            user_data: Dictionary containing user information from use case

        Returns:
            Dict[str, Any]: Formatted registration success response
        """
        return {
            "success": True,
            "message": "User registered successfully",
            "data": {
                "user": {
                    "id": user_data.get("id"),
                    "email": user_data.get("email"),
                    "username": user_data.get("username"),
                    "first_name": user_data.get("first_name"),
                    "last_name": user_data.get("last_name"),
                    "full_name": user_data.get("full_name"),
                    "status": user_data.get("status"),
                    "created_at": user_data.get("created_at")
                }
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_login_success(self, auth_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format successful login response.

        Args:
            auth_data: Dictionary containing authentication data from use case

        Returns:
            Dict[str, Any]: Formatted login success response
        """
        return {
            "success": True,
            "message": "Login successful",
            "data": {
                "access_token": auth_data.get("access_token"),
                "refresh_token": auth_data.get("refresh_token"),
                "token_type": auth_data.get("token_type", "Bearer"),
                "expires_in": auth_data.get("expires_in"),
                "user": auth_data.get("user_data")
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_logout_success(self) -> Dict[str, Any]:
        """
        Format successful logout response.

        Returns:
            Dict[str, Any]: Formatted logout success response
        """
        return {
            "success": True,
            "message": "Logout successful",
            "data": None,
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_token_refresh_success(self, token_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format successful token refresh response.

        Args:
            token_data: Dictionary containing new token information

        Returns:
            Dict[str, Any]: Formatted token refresh success response
        """
        return {
            "success": True,
            "message": "Token refreshed successfully",
            "data": {
                "access_token": token_data.get("access_token"),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in")
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_validation_error(self, errors: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format validation error response.

        Args:
            errors: Dictionary containing validation error details

        Returns:
            Dict[str, Any]: Formatted validation error response
        """
        return {
            "success": False,
            "message": "Validation failed",
            "error_code": "VALIDATION_ERROR",
            "data": None,
            "details": {
                "validation_errors": self._format_validation_errors(errors)
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_authentication_error(self, message: str) -> Dict[str, Any]:
        """
        Format authentication error response.

        Args:
            message: Error message describing the authentication failure

        Returns:
            Dict[str, Any]: Formatted authentication error response
        """
        return {
            "success": False,
            "message": message,
            "error_code": "AUTHENTICATION_ERROR",
            "data": None,
            "details": None,
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_token_validation_success(self, token_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format successful token validation response.

        Args:
            token_info: Dictionary containing token validation information

        Returns:
            Dict[str, Any]: Formatted token validation success response
        """
        return {
            "success": True,
            "message": "Token is valid",
            "data": {
                "valid": token_info.get("valid", True),
                "user_id": token_info.get("user_id"),
                "token_type": token_info.get("token_type"),
                "expires_at": token_info.get("expires_at"),
                "issued_at": token_info.get("issued_at")
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_token_validation_error(self, reason: str) -> Dict[str, Any]:
        """
        Format token validation error response.

        Args:
            reason: Reason why token validation failed

        Returns:
            Dict[str, Any]: Formatted token validation error response
        """
        return {
            "success": False,
            "message": "Token validation failed",
            "error_code": "INVALID_TOKEN",
            "data": {
                "valid": False,
                "reason": reason
            },
            "details": None,
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_server_error(self, message: str = "Internal server error") -> Dict[str, Any]:
        """
        Format server error response.

        Args:
            message: Error message describing the server error

        Returns:
            Dict[str, Any]: Formatted server error response
        """
        return {
            "success": False,
            "message": message,
            "error_code": "SERVER_ERROR",
            "data": None,
            "details": None,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _format_validation_errors(self, errors: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Format validation errors into a consistent structure.

        Args:
            errors: Raw validation errors from Pydantic or other validators

        Returns:
            Dict[str, List[str]]: Formatted validation errors by field
        """
        formatted_errors = {}

        if isinstance(errors, dict):
            for field, error_list in errors.items():
                if isinstance(error_list, list):
                    formatted_errors[field] = error_list
                else:
                    formatted_errors[field] = [str(error_list)]
        elif isinstance(errors, list):
            for error in errors:
                if isinstance(error, dict) and "loc" in error and "msg" in error:
                    field = ".".join(str(loc) for loc in error["loc"])
                    if field not in formatted_errors:
                        formatted_errors[field] = []
                    formatted_errors[field].append(error["msg"])
        else:
            formatted_errors["general"] = [str(errors)]

        return formatted_errors