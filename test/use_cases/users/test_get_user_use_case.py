import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime


from domain.entities.user import User, UserStatus
from domain.entities.auth_token import AuthToken, TokenType
from domain.exceptions import (
    UserNotFoundException
)

from use_cases.users.get_user_use_case import GetUserUseCase, GetUserRequest

class TestGetUserUseCase:

    @pytest.fixture
    def user_repository(self):
        return AsyncMock()

    @pytest.fixture
    def get_user_use_case(self, user_repository):
        return GetUserUseCase(user_repository)

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
            created_at=datetime(2023, 1, 1, 12, 0, 0),
            updated_at=datetime(2023, 1, 2, 12, 0, 0),
            last_login=datetime(2023, 1, 3, 12, 0, 0)
        )

    async def test_execute_returns_user_data_when_user_exists(self, get_user_use_case, user_repository, sample_user):
        user_repository.find_by_id.return_value = sample_user
        request = GetUserRequest(user_id="user-123")

        result = await get_user_use_case.execute(request)

        assert result.success is True
        assert result.user_data["id"] == "user-123"
        assert result.user_data["email"] == "test@example.com"
        assert result.user_data["username"] == "testuser"
        assert result.user_data["first_name"] == "John"
        assert result.user_data["last_name"] == "Doe"
        assert result.user_data["full_name"] == "John Doe"
        assert result.user_data["status"] == "active"
        assert result.user_data["created_at"] == "2023-01-01T12:00:00"
        assert result.user_data["updated_at"] == "2023-01-02T12:00:00"
        assert result.user_data["last_login"] == "2023-01-03T12:00:00"

    async def test_execute_returns_none_timestamps_when_user_has_none_values(self, get_user_use_case, user_repository):
        user = User(
            id="user-123",
            email="test@example.com",
            username="testuser",
            password_hash="hashed_password",
            first_name="John",
            last_name="Doe",
            status=UserStatus.ACTIVE,
            created_at=None,
            updated_at=None,
            last_login=None
        )
        user_repository.find_by_id.return_value = user
        request = GetUserRequest(user_id="user-123")

        result = await get_user_use_case.execute(request)

        assert result.user_data["created_at"] is None
        assert result.user_data["updated_at"] is None
        assert result.user_data["last_login"] is None

    async def test_execute_raises_user_not_found_exception_when_user_does_not_exist(self, get_user_use_case, user_repository):
        user_repository.find_by_id.return_value = None
        request = GetUserRequest(user_id="nonexistent-user")

        with pytest.raises(UserNotFoundException):
            await get_user_use_case.execute(request)

    async def test_execute_calls_repository_with_correct_user_id(self, get_user_use_case, user_repository, sample_user):
        user_repository.find_by_id.return_value = sample_user
        request = GetUserRequest(user_id="user-123")

        await get_user_use_case.execute(request)

        user_repository.find_by_id.assert_called_once_with("user-123")