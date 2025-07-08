import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta

from domain.entities.user import User, UserStatus
from domain.exceptions import (
    UserNotFoundException,
    UserAlreadyExistsException,
)

from use_cases.users.update_user_use_case import UpdateUserUseCase, UpdateUserRequest


class TestUpdateUserUseCase:

    @pytest.fixture
    def user_repository(self):
        return AsyncMock()

    @pytest.fixture
    def update_use_case(self, user_repository):
        return UpdateUserUseCase(user_repository)

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

    async def test_execute_raises_user_not_found_exception_when_user_does_not_exist(self, update_use_case,
                                                                                    user_repository):
        user_repository.find_by_id.return_value = None
        request = UpdateUserRequest(user_id="nonexistent-user")

        with pytest.raises(UserNotFoundException):
            await update_use_case.execute(request)

    async def test_execute_raises_user_already_exists_exception_when_username_taken(self, update_use_case,
                                                                                    user_repository, sample_user):
        user_repository.find_by_id.return_value = sample_user
        existing_user = User(
            id="other-user",
            email="other@example.com",
            username="newusername",
            password_hash="hash",
            first_name="Other",
            last_name="User",
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_login=None
        )
        user_repository.find_by_username.return_value = existing_user
        request = UpdateUserRequest(user_id="user-123", username="newusername")

        with pytest.raises(UserAlreadyExistsException):
            await update_use_case.execute(request)

    async def test_execute_allows_keeping_same_username(self, update_use_case, user_repository, sample_user):
        user_repository.find_by_id.return_value = sample_user
        user_repository.find_by_username.return_value = sample_user
        user_repository.update.return_value = sample_user
        request = UpdateUserRequest(user_id="user-123", username="testuser")

        result = await update_use_case.execute(request)

        assert result.success is True