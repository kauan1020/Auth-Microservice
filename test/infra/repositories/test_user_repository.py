import pytest
from unittest.mock import AsyncMock, Mock, MagicMock
from datetime import datetime, timedelta
from unittest.mock import patch
import uuid

from domain.entities.user import User, UserStatus
from domain.exceptions import UserNotFoundException
from infra.repositories.user_repository import UserRepository

class TestUserRepository:

    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.rollback = AsyncMock()
        session.flush = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        session.delete = AsyncMock()
        return session

    @pytest.fixture
    def user_repository(self, mock_session):
        return UserRepository(mock_session)

    @pytest.fixture
    def sample_user(self):
        return User(
            id=None,
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
    def sample_user_model(self):
        model = Mock()
        model.id = uuid.uuid4()
        model.email = "test@example.com"
        model.username = "testuser"
        model.password_hash = "hashed_password"
        model.first_name = "John"
        model.last_name = "Doe"
        model.status = Mock()
        model.status.value = "active"
        model.created_at = datetime.utcnow()
        model.updated_at = datetime.utcnow()
        model.last_login = None
        return model

    async def test_create_successfully_creates_user_when_all_data_valid(self, user_repository, mock_session,
                                                                        sample_user, sample_user_model):
        mock_session.add = Mock()
        mock_session.refresh.return_value = None
        sample_user_model.id = uuid.uuid4()

        with patch.object(user_repository, '_map_model_to_entity') as mock_map:
            mock_map.return_value = User(
                id=str(sample_user_model.id),
                email=sample_user.email,
                username=sample_user.username,
                password_hash=sample_user.password_hash,
                first_name=sample_user.first_name,
                last_name=sample_user.last_name,
                status=sample_user.status,
                created_at=sample_user.created_at,
                updated_at=sample_user.updated_at,
                last_login=sample_user.last_login
            )

            result = await user_repository.create(sample_user)

            assert result.email == sample_user.email
            assert result.username == sample_user.username
            mock_session.add.assert_called_once()
            mock_session.flush.assert_called_once()

    async def test_find_by_id_returns_user_when_user_exists(self, user_repository, mock_session, sample_user_model):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_user_model
        mock_session.execute.return_value = mock_result

        with patch.object(user_repository, '_map_model_to_entity') as mock_map:
            expected_user = User(
                id=str(sample_user_model.id),
                email=sample_user_model.email,
                username=sample_user_model.username,
                password_hash=sample_user_model.password_hash,
                first_name=sample_user_model.first_name,
                last_name=sample_user_model.last_name,
                status=UserStatus.ACTIVE,
                created_at=sample_user_model.created_at,
                updated_at=sample_user_model.updated_at,
                last_login=sample_user_model.last_login
            )
            mock_map.return_value = expected_user

            result = await user_repository.find_by_id(str(sample_user_model.id))

            assert result == expected_user
            mock_session.execute.assert_called_once()

    async def test_find_by_id_returns_none_when_user_not_found(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await user_repository.find_by_id("nonexistent-id")

        assert result is None

    async def test_find_by_id_returns_none_when_invalid_uuid(self, user_repository, mock_session):
        result = await user_repository.find_by_id("invalid-uuid")

        assert result is None

    async def test_find_by_email_returns_user_when_user_exists(self, user_repository, mock_session, sample_user_model):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_user_model
        mock_session.execute.return_value = mock_result

        with patch.object(user_repository, '_map_model_to_entity') as mock_map:
            expected_user = User(
                id=str(sample_user_model.id),
                email=sample_user_model.email,
                username=sample_user_model.username,
                password_hash=sample_user_model.password_hash,
                first_name=sample_user_model.first_name,
                last_name=sample_user_model.last_name,
                status=UserStatus.ACTIVE,
                created_at=sample_user_model.created_at,
                updated_at=sample_user_model.updated_at,
                last_login=sample_user_model.last_login
            )
            mock_map.return_value = expected_user

            result = await user_repository.find_by_email("test@example.com")

            assert result == expected_user
            mock_session.execute.assert_called_once()

    async def test_find_by_email_returns_none_when_user_not_found(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await user_repository.find_by_email("nonexistent@example.com")

        assert result is None

    async def test_find_by_username_returns_user_when_user_exists(self, user_repository, mock_session,
                                                                  sample_user_model):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_user_model
        mock_session.execute.return_value = mock_result

        with patch.object(user_repository, '_map_model_to_entity') as mock_map:
            expected_user = User(
                id=str(sample_user_model.id),
                email=sample_user_model.email,
                username=sample_user_model.username,
                password_hash=sample_user_model.password_hash,
                first_name=sample_user_model.first_name,
                last_name=sample_user_model.last_name,
                status=UserStatus.ACTIVE,
                created_at=sample_user_model.created_at,
                updated_at=sample_user_model.updated_at,
                last_login=sample_user_model.last_login
            )
            mock_map.return_value = expected_user

            result = await user_repository.find_by_username("testuser")

            assert result == expected_user
            mock_session.execute.assert_called_once()

    async def test_find_by_username_returns_none_when_user_not_found(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await user_repository.find_by_username("nonexistent")

        assert result is None

    async def test_update_successfully_updates_user_when_user_exists(self, user_repository, mock_session, sample_user,
                                                                     sample_user_model):
        sample_user.id = str(uuid.uuid4())
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_user_model
        mock_session.execute.return_value = mock_result

        with patch.object(user_repository, '_map_model_to_entity') as mock_map:
            updated_user = User(
                id=sample_user.id,
                email=sample_user.email,
                username=sample_user.username,
                password_hash=sample_user.password_hash,
                first_name=sample_user.first_name,
                last_name=sample_user.last_name,
                status=sample_user.status,
                created_at=sample_user.created_at,
                updated_at=sample_user.updated_at,
                last_login=sample_user.last_login
            )
            mock_map.return_value = updated_user

            result = await user_repository.update(sample_user)

            assert result == updated_user
            mock_session.flush.assert_called_once()
            mock_session.refresh.assert_called_once()

    async def test_update_raises_user_not_found_exception_when_user_not_found(self, user_repository, mock_session,
                                                                              sample_user):
        sample_user.id = str(uuid.uuid4())
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        with pytest.raises(UserNotFoundException):
            await user_repository.update(sample_user)

    async def test_update_raises_user_not_found_exception_when_invalid_uuid(self, user_repository, mock_session,
                                                                            sample_user):
        sample_user.id = "invalid-uuid"

        with pytest.raises(UserNotFoundException):
            await user_repository.update(sample_user)

    async def test_delete_returns_true_when_user_deleted_successfully(self, user_repository, mock_session,
                                                                      sample_user_model):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_user_model
        mock_session.execute.return_value = mock_result

        result = await user_repository.delete(str(sample_user_model.id))

        assert result is True
        mock_session.delete.assert_called_once()
        mock_session.flush.assert_called_once()

    async def test_delete_returns_false_when_user_not_found(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await user_repository.delete("nonexistent-id")

        assert result is False

    async def test_delete_returns_false_when_invalid_uuid(self, user_repository, mock_session):
        result = await user_repository.delete("invalid-uuid")

        assert result is False

    async def test_exists_by_email_returns_true_when_user_exists(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar.return_value = 1
        mock_session.execute.return_value = mock_result

        result = await user_repository.exists_by_email("test@example.com")

        assert result is True

    async def test_exists_by_email_returns_false_when_user_not_found(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar.return_value = 0
        mock_session.execute.return_value = mock_result

        result = await user_repository.exists_by_email("nonexistent@example.com")

        assert result is False

    async def test_exists_by_username_returns_true_when_user_exists(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar.return_value = 1
        mock_session.execute.return_value = mock_result

        result = await user_repository.exists_by_username("testuser")

        assert result is True

    async def test_exists_by_username_returns_false_when_user_not_found(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar.return_value = 0
        mock_session.execute.return_value = mock_result

        result = await user_repository.exists_by_username("nonexistent")

        assert result is False

    async def test_list_users_returns_list_of_users(self, user_repository, mock_session, sample_user_model):
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = [sample_user_model]
        mock_session.execute.return_value = mock_result

        with patch.object(user_repository, '_map_model_to_entity') as mock_map:
            expected_user = User(
                id=str(sample_user_model.id),
                email=sample_user_model.email,
                username=sample_user_model.username,
                password_hash=sample_user_model.password_hash,
                first_name=sample_user_model.first_name,
                last_name=sample_user_model.last_name,
                status=UserStatus.ACTIVE,
                created_at=sample_user_model.created_at,
                updated_at=sample_user_model.updated_at,
                last_login=sample_user_model.last_login
            )
            mock_map.return_value = expected_user

            result = await user_repository.list_users(skip=0, limit=10)

            assert len(result) == 1
            assert result[0] == expected_user

    async def test_count_users_returns_correct_count(self, user_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar.return_value = 5
        mock_session.execute.return_value = mock_result

        result = await user_repository.count_users()

        assert result == 5