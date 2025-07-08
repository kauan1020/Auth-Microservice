import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
import smtplib
import httpx

from infra.presenters.auth_presenter import AuthPresenter
from infra.presenters.user_presenter import UserPresenter
from infra.gateways.email_gateway import EmailGateway


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


class TestEmailGateway:

    @pytest.fixture
    def email_gateway(self):
        return EmailGateway(
            smtp_host="localhost",
            smtp_port=587,
            smtp_username="test@example.com",
            smtp_password="password",
            from_email="noreply@test.com",
            from_name="Test Service",
            use_tls=True,
            sendgrid_api_key=None
        )

    @pytest.fixture
    def sendgrid_email_gateway(self):
        return EmailGateway(
            smtp_host="localhost",
            smtp_port=587,
            smtp_username="test@example.com",
            smtp_password="password",
            from_email="noreply@test.com",
            from_name="Test Service",
            use_tls=True,
            sendgrid_api_key="test_api_key"
        )

    async def test_send_welcome_email_returns_true_when_email_sent_successfully(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = True

            result = await email_gateway.send_welcome_email("test@example.com", "John Doe")

            assert result is True
            mock_send.assert_called_once()

    async def test_send_welcome_email_returns_false_when_email_sending_fails(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = False

            result = await email_gateway.send_welcome_email("test@example.com", "John Doe")

            assert result is False

    async def test_send_welcome_email_returns_false_when_exception_occurs(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.side_effect = Exception("Email error")

            result = await email_gateway.send_welcome_email("test@example.com", "John Doe")

            assert result is False

    async def test_send_password_reset_email_returns_true_when_email_sent_successfully(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = True

            result = await email_gateway.send_password_reset_email("test@example.com", "reset_token_123")

            assert result is True
            mock_send.assert_called_once()

    async def test_send_password_reset_email_returns_false_when_email_sending_fails(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = False

            result = await email_gateway.send_password_reset_email("test@example.com", "reset_token_123")

            assert result is False

    async def test_send_password_reset_email_returns_false_when_exception_occurs(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.side_effect = Exception("Email error")

            result = await email_gateway.send_password_reset_email("test@example.com", "reset_token_123")

            assert result is False

    async def test_send_login_notification_returns_true_when_email_sent_successfully(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = True

            result = await email_gateway.send_login_notification("test@example.com", "John Doe", "2023-01-01 12:00:00")

            assert result is True
            mock_send.assert_called_once()

    async def test_send_login_notification_returns_false_when_email_sending_fails(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = False

            result = await email_gateway.send_login_notification("test@example.com", "John Doe", "2023-01-01 12:00:00")

            assert result is False

    async def test_send_login_notification_returns_false_when_exception_occurs(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.side_effect = Exception("Email error")

            result = await email_gateway.send_login_notification("test@example.com", "John Doe", "2023-01-01 12:00:00")

            assert result is False

    async def test_send_security_alert_returns_true_when_email_sent_successfully(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = True

            result = await email_gateway.send_security_alert("test@example.com", "Suspicious login attempt")

            assert result is True
            mock_send.assert_called_once()

    async def test_send_security_alert_returns_false_when_email_sending_fails(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.return_value = False

            result = await email_gateway.send_security_alert("test@example.com", "Suspicious login attempt")

            assert result is False

    async def test_send_security_alert_returns_false_when_exception_occurs(self, email_gateway):
        with patch.object(email_gateway, '_send_email') as mock_send:
            mock_send.side_effect = Exception("Email error")

            result = await email_gateway.send_security_alert("test@example.com", "Suspicious login attempt")

            assert result is False

    async def test_send_email_uses_sendgrid_when_api_key_provided(self, sendgrid_email_gateway):
        with patch.object(sendgrid_email_gateway, '_send_via_sendgrid') as mock_sendgrid:
            mock_sendgrid.return_value = True

            result = await sendgrid_email_gateway._send_email(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is True
            mock_sendgrid.assert_called_once()

    async def test_send_email_uses_smtp_when_no_api_key_provided(self, email_gateway):
        with patch.object(email_gateway, '_send_via_smtp') as mock_smtp:
            mock_smtp.return_value = True

            result = await email_gateway._send_email(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is True
            mock_smtp.assert_called_once()

    async def test_send_via_smtp_returns_true_when_email_sent_successfully(self, email_gateway):
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_server.starttls = Mock()
            mock_server.login = Mock()
            mock_server.send_message = Mock()

            result = await email_gateway._send_via_smtp(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is True
            mock_server.send_message.assert_called_once()

    async def test_send_via_smtp_returns_false_when_exception_occurs(self, email_gateway):
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = Exception("SMTP error")

            result = await email_gateway._send_via_smtp(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is False

    async def test_send_via_smtp_handles_tls_configuration(self, email_gateway):
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_server.starttls = Mock()
            mock_server.login = Mock()
            mock_server.send_message = Mock()

            await email_gateway._send_via_smtp(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            mock_server.starttls.assert_called_once()

    async def test_send_via_smtp_handles_authentication(self, email_gateway):
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_server.starttls = Mock()
            mock_server.login = Mock()
            mock_server.send_message = Mock()

            await email_gateway._send_via_smtp(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            mock_server.login.assert_called_once_with("test@example.com", "password")

    async def test_send_via_sendgrid_returns_true_when_email_sent_successfully(self, sendgrid_email_gateway):
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 202
            mock_response.raise_for_status = Mock()

            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

            result = await sendgrid_email_gateway._send_via_sendgrid(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is True

    async def test_send_via_sendgrid_returns_false_when_api_returns_error(self, sendgrid_email_gateway):
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.text = "Bad Request"
            mock_response.raise_for_status = Mock()

            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

            result = await sendgrid_email_gateway._send_via_sendgrid(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is False

    async def test_send_via_sendgrid_returns_false_when_exception_occurs(self, sendgrid_email_gateway):
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.side_effect = Exception("SendGrid error")

            result = await sendgrid_email_gateway._send_via_sendgrid(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            assert result is False

    async def test_send_via_sendgrid_sends_correct_payload(self, sendgrid_email_gateway):
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 202
            mock_response.raise_for_status = Mock()

            mock_post = Mock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post

            await sendgrid_email_gateway._send_via_sendgrid(
                "test@example.com",
                "Test Subject",
                "<html>Test HTML</html>",
                "Test Text"
            )

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://api.sendgrid.com/v3/mail/send"
            assert "Authorization" in call_args[1]["headers"]
            assert call_args[1]["headers"]["Authorization"] == "Bearer test_api_key"

    def test_get_welcome_email_template_contains_user_name(self, email_gateway):
        user_name = "John Doe"

        template = email_gateway._get_welcome_email_template(user_name)

        assert user_name in template
        assert "Welcome" in template
        assert "html" in template.lower()

    def test_get_password_reset_email_template_contains_reset_link(self, email_gateway):
        reset_link = "https://example.com/reset?token=abc123"

        template = email_gateway._get_password_reset_email_template(reset_link)

        assert reset_link in template
        assert "Reset Password" in template
        assert "html" in template.lower()

    def test_get_login_notification_email_template_contains_user_info(self, email_gateway):
        user_name = "John Doe"
        login_time = "2023-01-01 12:00:00"

        template = email_gateway._get_login_notification_email_template(user_name, login_time)

        assert user_name in template
        assert login_time in template
        assert "New Login" in template
        assert "html" in template.lower()

    def test_get_security_alert_email_template_contains_alert_message(self, email_gateway):
        alert_message = "Suspicious login attempt from unknown device"

        template = email_gateway._get_security_alert_email_template(alert_message)

        assert alert_message in template
        assert "Security Alert" in template
        assert "html" in template.lower()

    def test_email_gateway_initialization_sets_correct_defaults(self):
        gateway = EmailGateway()

        assert gateway.smtp_host == "localhost"
        assert gateway.smtp_port == 587
        assert gateway.from_email == "noreply@fiap-x.com"
        assert gateway.from_name == "FIAP X Authentication"
        assert gateway.use_tls is True
        assert gateway.sendgrid_api_key is None

    def test_email_gateway_initialization_accepts_custom_values(self):
        gateway = EmailGateway(
            smtp_host="custom.host",
            smtp_port=25,
            from_email="custom@example.com",
            from_name="Custom Service",
            use_tls=False,
            sendgrid_api_key="custom_key"
        )

        assert gateway.smtp_host == "custom.host"
        assert gateway.smtp_port == 25
        assert gateway.from_email == "custom@example.com"
        assert gateway.from_name == "Custom Service"
        assert gateway.use_tls is False
        assert gateway.sendgrid_api_key == "custom_key"