from abc import ABC, abstractmethod


class EmailGatewayInterface(ABC):
    """
    Interface for email service operations.

    Defines the contract for sending various types of emails
    including welcome messages, password resets, and notifications.
    """

    @abstractmethod
    async def send_welcome_email(self, email: str, user_name: str) -> bool:
        """Send welcome email to new user."""
        pass

    @abstractmethod
    async def send_password_reset_email(self, email: str, reset_token: str) -> bool:
        """Send password reset email."""
        pass

    @abstractmethod
    async def send_login_notification(self, email: str, user_name: str, login_time: str) -> bool:
        """Send login notification email."""
        pass

    @abstractmethod
    async def send_security_alert(self, email: str, alert_message: str) -> bool:
        """Send security alert email."""
        pass
