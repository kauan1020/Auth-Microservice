import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timedelta

from domain.entities.user import User, UserStatus
from domain.exceptions import (
    UserNotFoundException,
    InvalidCredentialsException,
    WeakPasswordException
)

from use_cases.users.change_password_use_case import ChangePasswordUseCase, ChangePasswordRequest


class TestChangePasswordUseCase:

    @pytest.fixture
    def user_repository(self):
        return AsyncMock()

    @pytest.fixture
    def password_service(self):
        mock = Mock()
        mock.verify_password.return_value = True
        mock.validate_password_strength.return_value = {"is_valid": True, "feedback": []}
        mock.is_password_compromised.return_value = False
        mock.hash_password.return_value = "new_hashed_password"
        return mock

    @pytest.fixture
    def change_password_use_case(self, user_repository, password_service):
        return ChangePasswordUseCase(user_repository, password_service)

    @pytest.fixture
    def sample_user(self):
        return User(
            id="user-123",
            email="test@example.com",
            username="testuser",
            password_hash="old_hashed_password",
            first_name="John",
            last_name="Doe",
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_login=None
        )

    async def test_execute_successfully_changes_password_when_all_validations_pass(self, change_password_use_case,
                                                                                   user_repository, password_service,
                                                                                   sample_user):
        user_repository.find_by_id.return_value = sample_user
        user_repository.update.return_value = sample_user
        request = ChangePasswordRequest(
            user_id="user-123",
            current_password="old_password",
            new_password="NewSecurePassword123!"
        )

        result = await change_password_use_case.execute(request)

        assert result.success is True
        assert result.message == "Password changed successfully"
        password_service.verify_password.assert_called_once_with("old_password", "old_hashed_password")
        password_service.hash_password.assert_called_once_with("NewSecurePassword123!")
        user_repository.update.assert_called_once()

    async def test_execute_raises_user_not_found_exception_when_user_does_not_exist(self, change_password_use_case,
                                                                                    user_repository):
        user_repository.find_by_id.return_value = None
        request = ChangePasswordRequest(
            user_id="nonexistent-user",
            current_password="old_password",
            new_password="NewSecurePassword123!"
        )

        with pytest.raises(UserNotFoundException):
            await change_password_use_case.execute(request)

    async def test_execute_raises_invalid_credentials_exception_when_current_password_wrong(self,
                                                                                            change_password_use_case,
                                                                                            user_repository,
                                                                                            password_service,
                                                                                            sample_user):
        user_repository.find_by_id.return_value = sample_user
        password_service.verify_password.return_value = False
        request = ChangePasswordRequest(
            user_id="user-123",
            current_password="wrong_password",
            new_password="NewSecurePassword123!"
        )

        with pytest.raises(InvalidCredentialsException):
            await change_password_use_case.execute(request)

    async def test_execute_raises_weak_password_exception_when_new_password_is_weak(self, change_password_use_case,
                                                                                    user_repository, password_service,
                                                                                    sample_user):
        user_repository.find_by_id.return_value = sample_user
        password_service.validate_password_strength.return_value = {
            "is_valid": False,
            "feedback": ["Too weak"]
        }
        request = ChangePasswordRequest(
            user_id="user-123",
            current_password="old_password",
            new_password="weak"
        )

        with pytest.raises(WeakPasswordException):
            await change_password_use_case.execute(request)

    async def test_execute_raises_weak_password_exception_when_new_password_is_compromised(self,
                                                                                           change_password_use_case,
                                                                                           user_repository,
                                                                                           password_service,
                                                                                           sample_user):
        user_repository.find_by_id.return_value = sample_user
        password_service.is_password_compromised.return_value = True
        request = ChangePasswordRequest(
            user_id="user-123",
            current_password="old_password",
            new_password="compromised_password"
        )

        with pytest.raises(WeakPasswordException):
            await change_password_use_case.execute(request)