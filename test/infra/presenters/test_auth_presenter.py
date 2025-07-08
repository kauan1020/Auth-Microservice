import pytest
from infra.presenters.auth_presenter import AuthPresenter

class TestAuthPresenter:

    @pytest.fixture
    def auth_presenter(self):
        return AuthPresenter()

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
            "created_at": "2023-01-01T12:00:00"
        }

    @pytest.fixture
    def sample_auth_data(self):
        return {
            "access_token": "access_token_123",
            "refresh_token": "refresh_token_123",
            "token_type": "Bearer",
            "expires_in": 900,
            "user_data": {
                "id": "user-123",
                "email": "test@example.com"
            }
        }

    def test_present_registration_success_returns_correct_format(self, auth_presenter, sample_user_data):
        result = auth_presenter.present_registration_success(sample_user_data)

        assert result["success"] is True
        assert result["message"] == "User registered successfully"
        assert result["data"]["user"]["id"] == "user-123"
        assert result["data"]["user"]["email"] == "test@example.com"
        assert "timestamp" in result

    def test_present_login_success_returns_correct_format(self, auth_presenter, sample_auth_data):
        result = auth_presenter.present_login_success(sample_auth_data)

        assert result["success"] is True
        assert result["message"] == "Login successful"
        assert result["data"]["access_token"] == "access_token_123"
        assert result["data"]["refresh_token"] == "refresh_token_123"
        assert result["data"]["token_type"] == "Bearer"
        assert result["data"]["expires_in"] == 900
        assert "timestamp" in result

    def test_present_logout_success_returns_correct_format(self, auth_presenter):
        result = auth_presenter.present_logout_success()

        assert result["success"] is True
        assert result["message"] == "Logout successful"
        assert result["data"] is None
        assert "timestamp" in result

    def test_present_token_refresh_success_returns_correct_format(self, auth_presenter):
        token_data = {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": 900
        }

        result = auth_presenter.present_token_refresh_success(token_data)

        assert result["success"] is True
        assert result["message"] == "Token refreshed successfully"
        assert result["data"]["access_token"] == "new_access_token"
        assert result["data"]["token_type"] == "Bearer"
        assert result["data"]["expires_in"] == 900
        assert "timestamp" in result

    def test_present_validation_error_returns_correct_format(self, auth_presenter):
        errors = {"email": ["Invalid email format"], "password": ["Password too weak"]}

        result = auth_presenter.present_validation_error(errors)

        assert result["success"] is False
        assert result["message"] == "Validation failed"
        assert result["error_code"] == "VALIDATION_ERROR"
        assert result["details"]["validation_errors"]["email"] == ["Invalid email format"]
        assert result["details"]["validation_errors"]["password"] == ["Password too weak"]
        assert "timestamp" in result

    def test_present_authentication_error_returns_correct_format(self, auth_presenter):
        message = "Invalid credentials"

        result = auth_presenter.present_authentication_error(message)

        assert result["success"] is False
        assert result["message"] == "Invalid credentials"
        assert result["error_code"] == "AUTHENTICATION_ERROR"
        assert result["data"] is None
        assert "timestamp" in result

    def test_present_token_validation_success_returns_correct_format(self, auth_presenter):
        token_info = {
            "valid": True,
            "user_id": "user-123",
            "token_type": "access",
            "expires_at": "2023-12-31T23:59:59",
            "issued_at": "2023-12-31T12:00:00"
        }

        result = auth_presenter.present_token_validation_success(token_info)

        assert result["success"] is True
        assert result["message"] == "Token is valid"
        assert result["data"]["valid"] is True
        assert result["data"]["user_id"] == "user-123"
        assert "timestamp" in result

    def test_present_token_validation_error_returns_correct_format(self, auth_presenter):
        reason = "Token expired"

        result = auth_presenter.present_token_validation_error(reason)

        assert result["success"] is False
        assert result["message"] == "Token validation failed"
        assert result["error_code"] == "INVALID_TOKEN"
        assert result["data"]["valid"] is False
        assert result["data"]["reason"] == "Token expired"
        assert "timestamp" in result

    def test_present_server_error_returns_correct_format(self, auth_presenter):
        message = "Database connection failed"

        result = auth_presenter.present_server_error(message)

        assert result["success"] is False
        assert result["message"] == "Database connection failed"
        assert result["error_code"] == "SERVER_ERROR"
        assert result["data"] is None
        assert "timestamp" in result

    def test_present_server_error_uses_default_message(self, auth_presenter):
        result = auth_presenter.present_server_error()

        assert result["message"] == "Internal server error"

    def test_format_validation_errors_handles_dict_format(self, auth_presenter):
        errors = {"email": ["Invalid format"], "password": ["Too weak"]}

        result = auth_presenter._format_validation_errors(errors)

        assert result["email"] == ["Invalid format"]
        assert result["password"] == ["Too weak"]

    def test_format_validation_errors_handles_list_format(self, auth_presenter):
        errors = [
            {"loc": ["email"], "msg": "Invalid format"},
            {"loc": ["password"], "msg": "Too weak"}
        ]

        result = auth_presenter._format_validation_errors(errors)

        assert result["email"] == ["Invalid format"]
        assert result["password"] == ["Too weak"]

    def test_format_validation_errors_handles_string_format(self, auth_presenter):
        errors = "General validation error"

        result = auth_presenter._format_validation_errors(errors)

        assert result["general"] == ["General validation error"]

    def test_format_validation_errors_handles_single_string_values(self, auth_presenter):
        errors = {"email": "Invalid format", "password": "Too weak"}

        result = auth_presenter._format_validation_errors(errors)

        assert result["email"] == ["Invalid format"]
        assert result["password"] == ["Too weak"]