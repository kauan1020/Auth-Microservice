import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta


from domain.entities.user import User, UserStatus
from domain.exceptions import (

    InvalidCredentialsException,
    UserBlockedException,
    UserInactiveException,
)

from use_cases.authenticate.login_use_case import LoginUseCase, LoginRequest


class TestLoginUseCase:

    @pytest.fixture
    def user_repository(self):
        return AsyncMock()

    @pytest.fixture
    def token_repository(self):
        return AsyncMock()

    @pytest.fixture
    def password_service(self):
        mock = Mock()
        mock.verify_password.return_value = True
        return mock

    @pytest.fixture
    def jwt_service(self):
        mock = Mock()
        mock.create_token_claims.return_value = {"user_id": "user-123"}
        mock.generate_token.return_value = "jwt_token"
        return mock

    @pytest.fixture
    def login_use_case(self, user_repository, token_repository, password_service, jwt_service):
        return LoginUseCase(user_repository, token_repository, password_service, jwt_service)

    @pytest.fixture
    def sample_user(self):
        return User(
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

    async def test_execute_successfully_authenticates_user_with_email(self, login_use_case, user_repository,
                                                                      token_repository, password_service, jwt_service,
                                                                      sample_user):
        user_repository.find_by_email.return_value = sample_user
        user_repository.update.return_value = sample_user
        token_repository.revoke_all_user_tokens.return_value = None
        token_repository.create.return_value = None

        request = LoginRequest(
            identifier="test@example.com",
            password="password123",
            remember_me=False
        )

        result = await login_use_case.execute(request)

        assert result.success is True
        assert result.access_token == "jwt_token"
        assert result.refresh_token == "jwt_token"
        assert result.token_type == "Bearer"
        assert result.user_data["id"] == "user-123"

    async def test_execute_successfully_authenticates_user_with_username(self, login_use_case, user_repository,
                                                                         token_repository, password_service,
                                                                         jwt_service, sample_user):
        user_repository.find_by_email.return_value = None
        user_repository.find_by_username.return_value = sample_user
        user_repository.update.return_value = sample_user
        token_repository.revoke_all_user_tokens.return_value = None
        token_repository.create.return_value = None

        request = LoginRequest(
            identifier="testuser",
            password="password123",
            remember_me=False
        )

        result = await login_use_case.execute(request)

        assert result.success is True

    async def test_execute_raises_invalid_credentials_exception_when_user_not_found(self, login_use_case,
                                                                                    user_repository):
        user_repository.find_by_email.return_value = None
        user_repository.find_by_username.return_value = None

        request = LoginRequest(
            identifier="nonexistent@example.com",
            password="password123",
            remember_me=False
        )

        with pytest.raises(InvalidCredentialsException):
            await login_use_case.execute(request)

    async def test_execute_raises_invalid_credentials_exception_when_password_wrong(self, login_use_case,
                                                                                    user_repository, password_service,
                                                                                    sample_user):
        user_repository.find_by_email.return_value = sample_user
        password_service.verify_password.return_value = False

        request = LoginRequest(
            identifier="test@example.com",
            password="wrong_password",
            remember_me=False
        )

        with pytest.raises(InvalidCredentialsException):
            await login_use_case.execute(request)

    async def test_execute_raises_user_blocked_exception_when_user_is_blocked(self, login_use_case, user_repository,
                                                                              sample_user):
        sample_user.status = UserStatus.BLOCKED
        user_repository.find_by_email.return_value = sample_user

        request = LoginRequest(
            identifier="test@example.com",
            password="password123",
            remember_me=False
        )

        with pytest.raises(UserBlockedException):
            await login_use_case.execute(request)

    async def test_execute_raises_user_inactive_exception_when_user_is_inactive(self, login_use_case, user_repository,
                                                                                sample_user):
        sample_user.status = UserStatus.INACTIVE
        user_repository.find_by_email.return_value = sample_user

        request = LoginRequest(
            identifier="test@example.com",
            password="password123",
            remember_me=False
        )

        with pytest.raises(UserInactiveException):
            await login_use_case.execute(request)

    async def test_execute_extends_token_expiration_when_remember_me_is_true(self, login_use_case, user_repository,
                                                                             token_repository, password_service,
                                                                             jwt_service, sample_user):
        user_repository.find_by_email.return_value = sample_user
        user_repository.update.return_value = sample_user
        token_repository.revoke_all_user_tokens.return_value = None
        token_repository.create.return_value = None

        request = LoginRequest(
            identifier="test@example.com",
            password="password123",
            remember_me=True
        )

        result = await login_use_case.execute(request)

        assert result.expires_in == 30 * 60 