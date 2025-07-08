from datetime import datetime
from typing import Dict, Any
from dataclasses import dataclass

from domain.entities.user import User, UserStatus
from domain.value_objects import Email, Username, Password
from domain.exceptions import UserAlreadyExistsException, WeakPasswordException
from interfaces.repositories.user_repository import UserRepositoryInterface
from interfaces.services.password_service import PasswordServiceInterface


@dataclass
class RegisterUserRequest:
    """
    Request data structure for user registration use case.

    Contains all the necessary information required to register
    a new user in the system.

    Attributes:
        email: User's email address
        username: User's chosen username
        password: User's plain text password
        first_name: User's first name
        last_name: User's last name
    """
    email: str
    username: str
    password: str
    first_name: str
    last_name: str


@dataclass
class RegisterUserResponse:
    """
    Response data structure for user registration use case.

    Contains the result of the registration operation including
    the created user information and operation status.

    Attributes:
        success: Whether the registration was successful
        user_id: ID of the created user
        message: Status message
        user_data: Dictionary containing user information
    """
    success: bool
    user_id: str
    message: str
    user_data: Dict[str, Any]


from interfaces.gateways.email_gateway import EmailGatewayInterface


class RegisterUserUseCase:
    """
    Use case for handling user registration operations.

    This use case encapsulates the business logic for registering new users,
    including validation, password hashing, and persistence operations.

    It ensures that all business rules are enforced during the registration
    process and handles various error scenarios appropriately.
    """

    def __init__(self,
                 user_repository: UserRepositoryInterface,
                 password_service: PasswordServiceInterface,
                 email_gateway: EmailGatewayInterface):
        """
        Initialize the register user use case.

        Args:
            user_repository: Repository for user data operations
            password_service: Service for password management
            email_gateway: Gateway for sending emails
        """
        self.user_repository = user_repository
        self.password_service = password_service
        self.email_gateway = email_gateway

    async def execute(self, request: RegisterUserRequest) -> RegisterUserResponse:
        """
        Execute the user registration use case.

        Args:
            request: Registration request containing user data

        Returns:
            RegisterUserResponse: Result of the registration operation

        Raises:
            UserAlreadyExistsException: If user with email/username exists
            WeakPasswordException: If password doesn't meet requirements
            ValueError: If input validation fails
        """
        await self._validate_user_uniqueness(request.email, request.username)

        self._validate_password_strength(request.password)

        user = await self._create_user(request)

        created_user = await self.user_repository.create(user)

        # Enviar email de boas-vindas
        await self._send_welcome_email(created_user)

        return RegisterUserResponse(
            success=True,
            user_id=created_user.id,
            message="User registered successfully",
            user_data={
                "id": created_user.id,
                "email": created_user.email,
                "username": created_user.username,
                "first_name": created_user.first_name,
                "last_name": created_user.last_name,
                "full_name": created_user.get_full_name(),
                "status": created_user.status.value,
                "created_at": created_user.created_at.isoformat() if created_user.created_at else None
            }
        )

    async def _validate_user_uniqueness(self, email: str, username: str) -> None:
        """
        Validate that email and username are unique in the system.

        Args:
            email: Email address to validate
            username: Username to validate

        Raises:
            UserAlreadyExistsException: If email or username already exists
        """
        if await self.user_repository.exists_by_email(email):
            raise UserAlreadyExistsException("email", email)

        if await self.user_repository.exists_by_username(username):
            raise UserAlreadyExistsException("username", username)

    def _validate_password_strength(self, password: str) -> None:
        """
        Validate password strength requirements.

        Args:
            password: Plain text password to validate

        Raises:
            WeakPasswordException: If password doesn't meet requirements
        """
        validation_result = self.password_service.validate_password_strength(password)

        if not validation_result["is_valid"]:
            feedback = ", ".join(validation_result["feedback"])
            raise WeakPasswordException(feedback)

        if self.password_service.is_password_compromised(password):
            raise WeakPasswordException("Password has been compromised in data breaches")

    async def _create_user(self, request: RegisterUserRequest) -> User:
        """
        Create a new User entity from the registration request.

        Args:
            request: Registration request data

        Returns:
            User: Created user entity
        """
        email = Email(request.email)
        username = Username(request.username)
        password = Password(request.password)

        password_hash = self.password_service.hash_password(password.value)

        now = datetime.utcnow()

        return User(
            id=None,
            email=email.value,
            username=username.value,
            password_hash=password_hash,
            first_name=request.first_name.strip(),
            last_name=request.last_name.strip(),
            status=UserStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            last_login=None
        )

    async def _send_welcome_email(self, user: User) -> None:
        """
        Send welcome email to the newly registered user.

        Args:
            user: The newly created user entity
        """
        try:
            await self.email_gateway.send_welcome_email(
                email=user.email,
                user_name=user.get_full_name()
            )
        except Exception as e:
            print(f"Failed to send welcome email to {user.email}: {str(e)}")