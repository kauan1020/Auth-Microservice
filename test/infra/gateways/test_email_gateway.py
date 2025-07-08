import pytest
from unittest.mock import Mock, patch

from infra.gateways.email_gateway import EmailGateway

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