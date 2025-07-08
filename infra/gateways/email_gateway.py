import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any
import logging
import json
import httpx

from interfaces.gateways.email_gateway import EmailGatewayInterface

logger = logging.getLogger(__name__)


class EmailGateway(EmailGatewayInterface):
    """
    Implementation of email service operations using SMTP and external services.

    This gateway handles email sending operations including welcome emails,
    password reset notifications, login alerts, and security notifications.

    It supports both SMTP (local/custom servers) and external email services
    like SendGrid, with fallback mechanisms and proper error handling.
    """

    def __init__(self,
                 smtp_host: str = "localhost",
                 smtp_port: int = 587,
                 smtp_username: str = "",
                 smtp_password: str = "",
                 from_email: str = "noreply@fiap-x.com",
                 from_name: str = "FIAP X Authentication",
                 use_tls: bool = True,
                 sendgrid_api_key: str = None):
        """
        Initialize email gateway with configuration.

        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_username: SMTP authentication username
            smtp_password: SMTP authentication password
            from_email: Default sender email address
            from_name: Default sender name
            use_tls: Whether to use TLS encryption
            sendgrid_api_key: SendGrid API key for external service
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.from_name = from_name
        self.use_tls = use_tls
        self.sendgrid_api_key = sendgrid_api_key

    async def send_welcome_email(self, email: str, user_name: str) -> bool:
        """
        Send welcome email to new user.

        Args:
            email: Recipient email address
            user_name: Name of the new user

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            subject = "Welcome to FIAP X Authentication Service!"

            html_content = self._get_welcome_email_template(user_name)
            text_content = f"""
            Welcome to FIAP X Authentication Service, {user_name}!

            Your account has been successfully created. You can now access all our services
            using your credentials.

            If you have any questions, please don't hesitate to contact our support team.

            Best regards,
            FIAP X Team
            """

            return await self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )

        except Exception as e:
            logger.error(f"Failed to send welcome email to {email}: {str(e)}")
            return False

    async def send_password_reset_email(self, email: str, reset_token: str) -> bool:
        """
        Send password reset email.

        Args:
            email: Recipient email address
            reset_token: Password reset token

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            subject = "Password Reset Request - FIAP X"

            reset_link = f"https://your-frontend-url.com/reset-password?token={reset_token}"

            html_content = self._get_password_reset_email_template(reset_link)
            text_content = f"""
            Password Reset Request

            You have requested to reset your password for your FIAP X account.

            Please click the following link to reset your password:
            {reset_link}

            This link will expire in 1 hour for security reasons.

            If you did not request this password reset, please ignore this email.

            Best regards,
            FIAP X Team
            """

            return await self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )

        except Exception as e:
            logger.error(f"Failed to send password reset email to {email}: {str(e)}")
            return False

    async def send_login_notification(self, email: str, user_name: str, login_time: str) -> bool:
        """
        Send login notification email.

        Args:
            email: Recipient email address
            user_name: Name of the user who logged in
            login_time: Timestamp of the login

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            subject = "New Login to Your FIAP X Account"

            html_content = self._get_login_notification_email_template(user_name, login_time)
            text_content = f"""
            New Login Notification

            Hello {user_name},

            We detected a new login to your FIAP X account at {login_time}.

            If this was you, no action is required.

            If you did not log in at this time, please secure your account immediately
            by changing your password.

            Best regards,
            FIAP X Security Team
            """

            return await self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )

        except Exception as e:
            logger.error(f"Failed to send login notification to {email}: {str(e)}")
            return False

    async def send_security_alert(self, email: str, alert_message: str) -> bool:
        """
        Send security alert email.

        Args:
            email: Recipient email address
            alert_message: Security alert message

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            subject = "Security Alert - FIAP X Account"

            html_content = self._get_security_alert_email_template(alert_message)
            text_content = f"""
            Security Alert

            We detected suspicious activity on your FIAP X account.

            Alert Details: {alert_message}

            Please review your account activity and secure your account if necessary.

            If you need assistance, please contact our support team immediately.

            Best regards,
            FIAP X Security Team
            """

            return await self._send_email(
                to_email=email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )

        except Exception as e:
            logger.error(f"Failed to send security alert to {email}: {str(e)}")
            return False

    async def _send_email(self, to_email: str, subject: str,
                          html_content: str, text_content: str) -> bool:
        """
        Send email using configured method (SMTP or SendGrid).

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email content
            text_content: Plain text email content

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if self.sendgrid_api_key:
            return await self._send_via_sendgrid(to_email, subject, html_content, text_content)
        else:
            return await self._send_via_smtp(to_email, subject, html_content, text_content)

    async def _send_via_smtp(self, to_email: str, subject: str,
                             html_content: str, text_content: str) -> bool:
        """
        Send email via SMTP server.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email content
            text_content: Plain text email content

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to_email

            text_part = MIMEText(text_content, 'plain')
            html_part = MIMEText(html_content, 'html')

            msg.attach(text_part)
            msg.attach(html_part)

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()

                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)

                server.send_message(msg)

            logger.info(f"Email sent successfully via SMTP to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email via SMTP to {to_email}: {str(e)}")
            return False

    async def _send_via_sendgrid(self, to_email: str, subject: str,
                                 html_content: str, text_content: str) -> bool:
        """
        Send email via SendGrid API.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email content
            text_content: Plain text email content

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            url = "https://api.sendgrid.com/v3/mail/send"
            headers = {
                "Authorization": f"Bearer {self.sendgrid_api_key}",
                "Content-Type": "application/json"
            }

            data = {
                "personalizations": [{
                    "to": [{"email": to_email}],
                    "subject": subject
                }],
                "from": {"email": self.from_email, "name": self.from_name},
                "content": [
                    {"type": "text/plain", "value": text_content},
                    {"type": "text/html", "value": html_content}
                ]
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers, json=data)

                if response.status_code == 202:
                    logger.info(f"Email sent successfully via SendGrid to {to_email}")
                    return True
                else:
                    logger.error(f"SendGrid API error: {response.status_code} - {response.text}")
                    return False

        except Exception as e:
            logger.error(f"Failed to send email via SendGrid to {to_email}: {str(e)}")
            return False

    def _get_welcome_email_template(self, user_name: str) -> str:
        """Get HTML template for welcome email."""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #007bff;">Welcome to FIAP X, {user_name}!</h1>
                <p>Thank you for creating your account with FIAP X Authentication Service.</p>
                <p>Your account is now active and ready to use. You can access all our services using your credentials.</p>
                <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                <p>Best regards,<br>The FIAP X Team</p>
            </div>
        </body>
        </html>
        """

    def _get_password_reset_email_template(self, reset_link: str) -> str:
        """Get HTML template for password reset email."""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #007bff;">Password Reset Request</h1>
                <p>You have requested to reset your password for your FIAP X account.</p>
                <p>Click the button below to reset your password:</p>
                <a href="{reset_link}" style="display: inline-block; background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0;">Reset Password</a>
                <p>This link will expire in 1 hour for security reasons.</p>
                <p>If you did not request this password reset, please ignore this email.</p>
                <p>Best regards,<br>The FIAP X Team</p>
            </div>
        </body>
        </html>
        """

    def _get_login_notification_email_template(self, user_name: str, login_time: str) -> str:
        """Get HTML template for login notification email."""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #28a745;">New Login Detected</h1>
                <p>Hello {user_name},</p>
                <p>We detected a new login to your FIAP X account at <strong>{login_time}</strong>.</p>
                <p>If this was you, no action is required.</p>
                <p>If you did not log in at this time, please secure your account immediately by changing your password.</p>
                <p>Best regards,<br>FIAP X Security Team</p>
            </div>
        </body>
        </html>
        """

    def _get_security_alert_email_template(self, alert_message: str) -> str:
        """Get HTML template for security alert email."""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #dc3545;">Security Alert</h1>
                <p>We detected suspicious activity on your FIAP X account.</p>
                <div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;">
                    <strong>Alert Details:</strong> {alert_message}
                </div>
                <p>Please review your account activity and secure your account if necessary.</p>
                <p>If you need assistance, please contact our support team immediately.</p>
                <p>Best regards,<br>FIAP X Security Team</p>
            </div>
        </body>
        </html>
        """