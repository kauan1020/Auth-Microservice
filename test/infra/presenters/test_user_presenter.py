import pytest


from infra.presenters.auth_presenter import AuthPresenter
from infra.presenters.user_presenter import UserPresenter

class TestUserPresenter:

    @pytest.fixture
    def user_presenter(self):
        return UserPresenter()

    @pytest.fixture
    def sample_user_data(self):
        return {
            "id": "user-123",
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "John",
            "last_name": "Doe",
            "full_name": "John Doe",
            "status": "active",
            "created_at": "2023-01-01T12:00:00",
            "updated_at": "2023-01-02T12:00:00",
            "last_login": "2023-01-03T12:00:00"
        }

    def test_present_user_profile_returns_correct_format(self, user_presenter, sample_user_data):
        result = user_presenter.present_user_profile(sample_user_data)

        assert result["success"] is True
        assert result["message"] == "User profile retrieved successfully"
        assert result["data"]["user"]["id"] == "user-123"
        assert result["data"]["user"]["email"] == "test@example.com"
        assert result["data"]["user"]["username"] == "testuser"
        assert result["data"]["user"]["first_name"] == "John"
        assert result["data"]["user"]["last_name"] == "Doe"
        assert result["data"]["user"]["full_name"] == "John Doe"
        assert result["data"]["user"]["status"] == "active"
        assert "timestamp" in result

    def test_present_profile_update_success_returns_correct_format(self, user_presenter, sample_user_data):
        result = user_presenter.present_profile_update_success(sample_user_data)

        assert result["success"] is True
        assert result["message"] == "Profile updated successfully"
        assert result["data"]["user"]["id"] == "user-123"
        assert result["data"]["user"]["email"] == "test@example.com"
        assert "timestamp" in result

    def test_present_password_change_success_returns_correct_format(self, user_presenter):
        result = user_presenter.present_password_change_success()

        assert result["success"] is True
        assert result["message"] == "Password changed successfully"
        assert result["data"]["password_changed"] is True
        assert "security_notice" in result["data"]
        assert "timestamp" in result

    def test_present_user_not_found_returns_correct_format(self, user_presenter):
        result = user_presenter.present_user_not_found()

        assert result["success"] is False
        assert result["message"] == "User not found"
        assert result["error_code"] == "USER_NOT_FOUND"
        assert result["data"] is None
        assert "reason" in result["details"]
        assert "timestamp" in result

    def test_present_user_already_exists_returns_correct_format(self, user_presenter):
        result = user_presenter.present_user_already_exists("email", "test@example.com")

        assert result["success"] is False
        assert result["message"] == "User with this email already exists"
        assert result["error_code"] == "USER_ALREADY_EXISTS"
        assert result["data"] is None
        assert result["details"]["field"] == "email"
        assert result["details"]["value"] == "test@example.com"
        assert "suggestion" in result["details"]
        assert "timestamp" in result

    def test_present_password_validation_error_returns_correct_format(self, user_presenter):
        feedback = "Password must be at least 8 characters"

        result = user_presenter.present_password_validation_error(feedback)

        assert result["success"] is False
        assert result["message"] == "Password does not meet security requirements"
        assert result["error_code"] == "WEAK_PASSWORD"
        assert result["data"] is None
        assert result["details"]["requirements"] == feedback
        assert "suggestions" in result["details"]
        assert "timestamp" in result

    def test_present_unauthorized_access_returns_correct_format(self, user_presenter):
        result = user_presenter.present_unauthorized_access()

        assert result["success"] is False
        assert result["message"] == "Unauthorized access"
        assert result["error_code"] == "UNAUTHORIZED"
        assert result["data"] is None
        assert "reason" in result["details"]
        assert "timestamp" in result

    def test_present_insufficient_permissions_returns_correct_format(self, user_presenter):
        result = user_presenter.present_insufficient_permissions()

        assert result["success"] is False
        assert result["message"] == "Insufficient permissions"
        assert result["error_code"] == "FORBIDDEN"
        assert result["data"] is None
        assert "reason" in result["details"]
        assert "timestamp" in result

    def test_present_validation_error_returns_correct_format(self, user_presenter):
        errors = {"first_name": ["Required field"], "last_name": ["Too long"]}

        result = user_presenter.present_validation_error(errors)

        assert result["success"] is False
        assert result["message"] == "Input validation failed"
        assert result["error_code"] == "VALIDATION_ERROR"
        assert result["data"] is None
        assert result["details"]["validation_errors"]["first_name"] == ["Required field"]
        assert result["details"]["validation_errors"]["last_name"] == ["Too long"]
        assert "timestamp" in result

    def test_present_server_error_returns_correct_format(self, user_presenter):
        message = "Database connection failed"

        result = user_presenter.present_server_error(message)

        assert result["success"] is False
        assert result["message"] == "Database connection failed"
        assert result["error_code"] == "SERVER_ERROR"
        assert result["data"] is None
        assert "timestamp" in result

    def test_present_server_error_uses_default_message(self, user_presenter):
        result = user_presenter.present_server_error()

        assert result["message"] == "Internal server error"

    def test_format_validation_errors_handles_dict_format(self, user_presenter):
        errors = {"first_name": ["Required"], "last_name": ["Too long"]}

        result = user_presenter._format_validation_errors(errors)

        assert result["first_name"] == ["Required"]
        assert result["last_name"] == ["Too long"]

    def test_format_validation_errors_handles_list_format(self, user_presenter):
        errors = [
            {"loc": ["first_name"], "msg": "Required"},
            {"loc": ["last_name"], "msg": "Too long"}
        ]

        result = user_presenter._format_validation_errors(errors)

        assert result["first_name"] == ["Required"]
        assert result["last_name"] == ["Too long"]

    def test_format_validation_errors_handles_string_format(self, user_presenter):
        errors = "General validation error"

        result = user_presenter._format_validation_errors(errors)

        assert result["general"] == ["General validation error"]
