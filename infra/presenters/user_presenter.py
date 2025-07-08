from typing import Dict, Any
from datetime import datetime

from interfaces.presenters.user_presenter import UserPresenterInterface


class UserPresenter(UserPresenterInterface):
    """
    Implementation of user data presentation.

    This presenter formats user-related responses according to API specifications,
    ensuring consistent response structure and proper data serialization for
    user management operations.

    It handles user profile data, update confirmations, and error responses
    related to user operations.
    """

    def present_user_profile(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format user profile response.

        Args:
            user_data: Dictionary containing user profile information

        Returns:
            Dict[str, Any]: Formatted user profile response
        """
        return {
            "success": True,
            "message": "User profile retrieved successfully",
            "data": {
                "user": {
                    "id": user_data.get("id"),
                    "email": user_data.get("email"),
                    "username": user_data.get("username"),
                    "first_name": user_data.get("first_name"),
                    "last_name": user_data.get("last_name"),
                    "full_name": user_data.get("full_name"),
                    "status": user_data.get("status"),
                    "created_at": user_data.get("created_at"),
                    "updated_at": user_data.get("updated_at"),
                    "last_login": user_data.get("last_login")
                }
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_profile_update_success(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format successful profile update response.

        Args:
            user_data: Dictionary containing updated user information

        Returns:
            Dict[str, Any]: Formatted profile update success response
        """
        return {
            "success": True,
            "message": "Profile updated successfully",
            "data": {
                "user": {
                    "id": user_data.get("id"),
                    "email": user_data.get("email"),
                    "username": user_data.get("username"),
                    "first_name": user_data.get("first_name"),
                    "last_name": user_data.get("last_name"),
                    "full_name": user_data.get("full_name"),
                    "status": user_data.get("status"),
                    "updated_at": user_data.get("updated_at")
                }
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_password_change_success(self) -> Dict[str, Any]:
        """
        Format successful password change response.

        Returns:
            Dict[str, Any]: Formatted password change success response
        """
        return {
            "success": True,
            "message": "Password changed successfully",
            "data": {
                "password_changed": True,
                "security_notice": "All active sessions have been terminated for security"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_user_not_found(self) -> Dict[str, Any]:
        """
        Format user not found error response.

        Returns:
            Dict[str, Any]: Formatted user not found error response
        """
        return {
            "success": False,
            "message": "User not found",
            "error_code": "USER_NOT_FOUND",
            "data": None,
            "details": {
                "reason": "The requested user does not exist or has been deleted"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_user_already_exists(self, field: str, value: str) -> Dict[str, Any]:
        """
        Format user already exists error response.

        Args:
            field: Field that already exists (email or username)
            value: Value that already exists

        Returns:
            Dict[str, Any]: Formatted user already exists error response
        """
        return {
            "success": False,
            "message": f"User with this {field} already exists",
            "error_code": "USER_ALREADY_EXISTS",
            "data": None,
            "details": {
                "field": field,
                "value": value,
                "suggestion": f"Please use a different {field}"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_password_validation_error(self, feedback: str) -> Dict[str, Any]:
        """
        Format password validation error response.

        Args:
            feedback: Password validation feedback message

        Returns:
            Dict[str, Any]: Formatted password validation error response
        """
        return {
            "success": False,
            "message": "Password does not meet security requirements",
            "error_code": "WEAK_PASSWORD",
            "data": None,
            "details": {
                "requirements": feedback,
                "suggestions": [
                    "Use at least 8 characters",
                    "Include uppercase and lowercase letters",
                    "Include numbers and special characters",
                    "Avoid common passwords and patterns"
                ]
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_unauthorized_access(self) -> Dict[str, Any]:
        """
        Format unauthorized access error response.

        Returns:
            Dict[str, Any]: Formatted unauthorized access error response
        """
        return {
            "success": False,
            "message": "Unauthorized access",
            "error_code": "UNAUTHORIZED",
            "data": None,
            "details": {
                "reason": "Valid authentication token required"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_insufficient_permissions(self) -> Dict[str, Any]:
        """
        Format insufficient permissions error response.

        Returns:
            Dict[str, Any]: Formatted insufficient permissions error response
        """
        return {
            "success": False,
            "message": "Insufficient permissions",
            "error_code": "FORBIDDEN",
            "data": None,
            "details": {
                "reason": "You don't have permission to perform this action"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def present_validation_error(self, errors: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format validation error response for user operations.

        Args:
            errors: Dictionary containing validation error details

        Returns:
            Dict[str, Any]: Formatted validation error response
        """
        return {
            "success": False,
            "message": "Input validation failed",
            "error_code": "VALIDATION_ERROR",
            "data": None,
            "details": {
                "validation_errors": self._format_validation_errors(errors)
            },
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

    def _format_validation_errors(self, errors: Dict[str, Any]) -> Dict[str, list]:
        """
        Format validation errors into a consistent structure.

        Args:
            errors: Raw validation errors

        Returns:
            Dict[str, list]: Formatted validation errors by field
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