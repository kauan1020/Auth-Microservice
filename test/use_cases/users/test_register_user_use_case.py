import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta

from domain.entities.user import User, UserStatus
from domain.exceptions import (
    UserAlreadyExistsException,
    WeakPasswordException
)

from use_cases.users.register_user_use_case import RegisterUserUseCase, RegisterUserRequest, RegisterUserResponse

class TestRegisterUserUseCase:

    @pytest.fixture
    def user_repository(self):
        return AsyncMock()

    @pytest.fixture
    def password_service(self):
        mock = Mock()
        mock.validate_password_strength.return_value = {"is_valid": True, "feedback": []}
        mock.is_password_compromised.return_value = False
        mock.hash_password.return_value = "hashed_password"
        return mock

    @pytest.fixture
    def email_gateway(self):
        mock = AsyncMock()
        mock.send_welcome_email.return_value = True
        return mock

    @pytest.fixture
    def register_use_case(self, user_repository, password_service, email_gateway):
        return RegisterUserUseCase(user_repository, password_service, email_gateway)

    @pytest.fixture
    def register_request(self):
        return RegisterUserRequest(
            email="test@example.com",
            username="testuser",
            password="SecurePassword123!",
            first_name="John",
            last_name="Doe"
        )

    async def test_execute_successfully_registers_user_when_all_validations_pass(self, register_use_case,
                                                                                 user_repository, password_service,
                                                                                 email_gateway, register_request):
        user_repository.exists_by_email.return_value = False
        user_repository.exists_by_username.return_value = False

        created_user = User(
            id="user-123",
            email="test@example.com",
            username="testuser",
            password_hash="hashed_password",
            first_name="John",
            last_name="Doe",
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_login=None
        )
        user_repository.create.return_value = created_user

        result = await register_use_case.execute(register_request)

        assert result.success is True
        assert result.user_id == "user-123"
        assert result.message == "User registered successfully"
        assert result.user_data["email"] == "test@example.com"
        user_repository.create.assert_called_once()
        email_gateway.send_welcome_email.assert_called_once()

    async def test_execute_raises_user_already_exists_exception_when_email_exists(self, register_use_case,
                                                                                  user_repository, register_request):
        user_repository.exists_by_email.return_value = True

        with pytest.raises(UserAlreadyExistsException):
            await register_use_case.execute(register_request)

    async def test_execute_raises_user_already_exists_exception_when_username_exists(self, register_use_case,
                                                                                     user_repository, register_request):
        user_repository.exists_by_email.return_value = False
        user_repository.exists_by_username.return_value = True

        with pytest.raises(UserAlreadyExistsException):
            await register_use_case.execute(register_request)

    async def test_execute_raises_weak_password_exception_when_password_is_weak(self, register_use_case,
                                                                                user_repository, password_service,
                                                                                register_request):
        user_repository.exists_by_email.return_value = False
        user_repository.exists_by_username.return_value = False
        password_service.validate_password_strength.return_value = {
            "is_valid": False,
            "feedback": ["Too weak"]
        }

        with pytest.raises(WeakPasswordException):
            await register_use_case.execute(register_request)

    async def test_execute_raises_weak_password_exception_when_password_is_compromised(self, register_use_case,
                                                                                       user_repository,
                                                                                       password_service,
                                                                                       register_request):
        user_repository.exists_by_email.return_value = False
        user_repository.exists_by_username.return_value = False
        password_service.is_password_compromised.return_value = True

        with pytest.raises(WeakPasswordException):
            await register_use_case.execute(register_request)

    async def test_execute_continues_when_email_sending_fails(self, register_use_case, user_repository,
                                                              password_service, email_gateway, register_request):
        user_repository.exists_by_email.return_value = False
        user_repository.exists_by_username.return_value = False
        email_gateway.send_welcome_email.side_effect = Exception("Email failed")

        created_user = User(
            id="user-123",
            email="test@example.com",
            username="testuser",
            password_hash="hashed_password",
            first_name="John",
            last_name="Doe",
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_login=None
        )
        user_repository.create.return_value = created_user

        result = await register_use_case.execute(register_request)

        assert result.success is True