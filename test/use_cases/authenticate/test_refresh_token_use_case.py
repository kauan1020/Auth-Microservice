import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta


from domain.entities.user import User, UserStatus
from domain.entities.auth_token import AuthToken, TokenType
from domain.exceptions import (
    UserNotFoundException,
    InvalidTokenException,
    TokenExpiredException,
    UserInactiveException,
    TokenRevokedException
)

from use_cases.authenticate.refresh_token_use_case import RefreshTokenUseCase, RefreshTokenRequest, RefreshTokenResponse


class TestRefreshTokenUseCase:

    @pytest.fixture
    def user_repository(self):
        return AsyncMock()

    @pytest.fixture
    def token_repository(self):
        return AsyncMock()

    @pytest.fixture
    def jwt_service(self):
        mock = Mock()
        mock.refresh_token_claims.return_value = {"username": "testuser"}
        mock.extract_user_id.return_value = "user-123"
        mock.create_token_claims.return_value = {"user_id": "user-123"}
        mock.generate_token.return_value = "new_access_token"
        return mock

    @pytest.fixture
    def refresh_use_case(self, user_repository, token_repository, jwt_service):
        return RefreshTokenUseCase(user_repository, token_repository, jwt_service)

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

    @pytest.fixture
    def valid_refresh_token(self):
        return AuthToken(
            token="valid_refresh_token",
            token_type=TokenType.REFRESH,
            user_id="user-123",
            expires_at=datetime.utcnow() + timedelta(days=30),
            created_at=datetime.utcnow(),
            is_revoked=False
        )

    async def test_execute_successfully_refreshes_token_when_all_validations_pass(self, refresh_use_case,
                                                                                  user_repository, token_repository,
                                                                                  jwt_service, sample_user,
                                                                                  valid_refresh_token):
        token_repository.find_by_token.return_value = valid_refresh_token
        user_repository.find_by_id.return_value = sample_user
        token_repository.create.return_value = None

        request = RefreshTokenRequest(refresh_token="valid_refresh_token")

        result = await refresh_use_case.execute(request)

        assert result.success is True
        assert result.access_token == "new_access_token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 15 * 60

    async def test_execute_raises_invalid_token_exception_when_token_not_found(self, refresh_use_case,
                                                                               token_repository):
        token_repository.find_by_token.return_value = None

        request = RefreshTokenRequest(refresh_token="nonexistent_token")

        with pytest.raises(InvalidTokenException):
            await refresh_use_case.execute(request)

    async def test_execute_raises_token_revoked_exception_when_token_is_revoked(self, refresh_use_case,
                                                                                token_repository, valid_refresh_token):
        valid_refresh_token.is_revoked = True
        token_repository.find_by_token.return_value = valid_refresh_token

        request = RefreshTokenRequest(refresh_token="revoked_token")

        with pytest.raises(TokenRevokedException):
            await refresh_use_case.execute(request)

    async def test_execute_raises_token_expired_exception_when_token_is_expired(self, refresh_use_case,
                                                                                token_repository, valid_refresh_token):
        valid_refresh_token.expires_at = datetime.utcnow() - timedelta(days=1)
        token_repository.find_by_token.return_value = valid_refresh_token

        request = RefreshTokenRequest(refresh_token="expired_token")

        with pytest.raises(TokenExpiredException):
            await refresh_use_case.execute(request)

    async def test_execute_raises_user_not_found_exception_when_user_does_not_exist(self, refresh_use_case,
                                                                                    user_repository, token_repository,
                                                                                    valid_refresh_token):
        token_repository.find_by_token.return_value = valid_refresh_token
        user_repository.find_by_id.return_value = None

        request = RefreshTokenRequest(refresh_token="valid_refresh_token")

        with pytest.raises(UserNotFoundException):
            await refresh_use_case.execute(request)

    async def test_execute_raises_user_inactive_exception_when_user_is_inactive(self, refresh_use_case, user_repository,
                                                                                token_repository, valid_refresh_token,
                                                                                sample_user):
        sample_user.status = UserStatus.INACTIVE
        token_repository.find_by_token.return_value = valid_refresh_token
        user_repository.find_by_id.return_value = sample_user

        request = RefreshTokenRequest(refresh_token="valid_refresh_token")

        with pytest.raises(UserInactiveException):
            await refresh_use_case.execute(request)