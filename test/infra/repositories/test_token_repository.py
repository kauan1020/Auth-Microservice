import pytest
from unittest.mock import AsyncMock, Mock, MagicMock
from datetime import datetime, timedelta
from unittest.mock import patch
import uuid

from domain.entities.auth_token import AuthToken, TokenType
from infra.repositories.token_repository import TokenRepository


class TestTokenRepository:

    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.flush = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.fixture
    def token_repository(self, mock_session):
        return TokenRepository(mock_session)

    @pytest.fixture
    def sample_auth_token(self):
        return AuthToken(
            token="sample_token",
            token_type=TokenType.ACCESS,
            user_id="user-123",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            created_at=datetime.utcnow(),
            is_revoked=False
        )

    @pytest.fixture
    def sample_token_model(self):
        model = Mock()
        model.token = "sample_token"
        model.token_type = Mock()
        model.token_type.value = "access"
        model.user_id = uuid.uuid4()
        model.expires_at = datetime.utcnow() + timedelta(hours=1)
        model.created_at = datetime.utcnow()
        model.is_revoked = False
        return model

    async def test_find_by_token_returns_token_when_token_exists(self, token_repository, mock_session,
                                                                 sample_token_model):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_token_model
        mock_session.execute.return_value = mock_result

        with patch.object(token_repository, '_map_model_to_entity') as mock_map:
            expected_token = AuthToken(
                token=sample_token_model.token,
                token_type=TokenType.ACCESS,
                user_id=str(sample_token_model.user_id),
                expires_at=sample_token_model.expires_at,
                created_at=sample_token_model.created_at,
                is_revoked=sample_token_model.is_revoked
            )
            mock_map.return_value = expected_token

            result = await token_repository.find_by_token("sample_token")

            assert result == expected_token
            mock_session.execute.assert_called_once()

    async def test_find_by_token_returns_none_when_token_not_found(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await token_repository.find_by_token("nonexistent_token")

        assert result is None

    async def test_find_by_user_id_returns_tokens_for_user(self, token_repository, mock_session, sample_token_model):
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = [sample_token_model]
        mock_session.execute.return_value = mock_result

        with patch.object(token_repository, '_map_model_to_entity') as mock_map:
            expected_token = AuthToken(
                token=sample_token_model.token,
                token_type=TokenType.ACCESS,
                user_id=str(sample_token_model.user_id),
                expires_at=sample_token_model.expires_at,
                created_at=sample_token_model.created_at,
                is_revoked=sample_token_model.is_revoked
            )
            mock_map.return_value = expected_token

            result = await token_repository.find_by_user_id(str(sample_token_model.user_id), TokenType.ACCESS)

            assert len(result) == 1
            assert result[0] == expected_token

    async def test_find_by_user_id_returns_empty_list_when_invalid_uuid(self, token_repository, mock_session):
        result = await token_repository.find_by_user_id("invalid-uuid", TokenType.ACCESS)

        assert result == []

    async def test_find_active_tokens_by_user_returns_active_tokens(self, token_repository, mock_session,
                                                                    sample_token_model):
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = [sample_token_model]
        mock_session.execute.return_value = mock_result

        with patch.object(token_repository, '_map_model_to_entity') as mock_map:
            expected_token = AuthToken(
                token=sample_token_model.token,
                token_type=TokenType.ACCESS,
                user_id=str(sample_token_model.user_id),
                expires_at=sample_token_model.expires_at,
                created_at=sample_token_model.created_at,
                is_revoked=sample_token_model.is_revoked
            )
            mock_map.return_value = expected_token

            result = await token_repository.find_active_tokens_by_user(str(sample_token_model.user_id))

            assert len(result) == 1
            assert result[0] == expected_token

    async def test_find_active_tokens_by_user_returns_empty_list_when_invalid_uuid(self, token_repository,
                                                                                   mock_session):
        result = await token_repository.find_active_tokens_by_user("invalid-uuid")

        assert result == []

    async def test_revoke_token_returns_true_when_token_revoked_successfully(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.rowcount = 1
        mock_session.execute.return_value = mock_result

        result = await token_repository.revoke_token("sample_token")

        assert result is True
        mock_session.flush.assert_called_once()

    async def test_revoke_token_returns_false_when_token_not_found(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.rowcount = 0
        mock_session.execute.return_value = mock_result

        result = await token_repository.revoke_token("nonexistent_token")

        assert result is False

    async def test_revoke_all_user_tokens_returns_count_of_revoked_tokens(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.rowcount = 3
        mock_session.execute.return_value = mock_result

        result = await token_repository.revoke_all_user_tokens(str(uuid.uuid4()))

        assert result == 3
        mock_session.flush.assert_called_once()

    async def test_revoke_all_user_tokens_returns_zero_when_invalid_uuid(self, token_repository, mock_session):
        result = await token_repository.revoke_all_user_tokens("invalid-uuid")

        assert result == 0

    async def test_revoke_user_tokens_by_type_returns_count_of_revoked_tokens(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.rowcount = 2
        mock_session.execute.return_value = mock_result

        result = await token_repository.revoke_user_tokens_by_type(str(uuid.uuid4()), TokenType.ACCESS)

        assert result == 2
        mock_session.flush.assert_called_once()

    async def test_revoke_user_tokens_by_type_returns_zero_when_invalid_uuid(self, token_repository, mock_session):
        result = await token_repository.revoke_user_tokens_by_type("invalid-uuid", TokenType.ACCESS)

        assert result == 0

    async def test_cleanup_expired_tokens_returns_count_of_deleted_tokens(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.rowcount = 5
        mock_session.execute.return_value = mock_result

        result = await token_repository.cleanup_expired_tokens()

        assert result == 5
        mock_session.flush.assert_called_once()

    async def test_is_token_revoked_returns_true_when_token_is_revoked(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = True
        mock_session.execute.return_value = mock_result

        result = await token_repository.is_token_revoked("revoked_token")

        assert result is True

    async def test_is_token_revoked_returns_false_when_token_is_not_revoked(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = False
        mock_session.execute.return_value = mock_result

        result = await token_repository.is_token_revoked("active_token")

        assert result is False

    async def test_is_token_revoked_returns_false_when_token_not_found(self, token_repository, mock_session):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await token_repository.is_token_revoked("nonexistent_token")

        assert result is False

    async def test_update_token_returns_updated_token(self, token_repository, mock_session, sample_auth_token):
        mock_result = Mock()
        mock_result.scalar_one.return_value = Mock()
        mock_session.execute.return_value = mock_result

        with patch.object(token_repository, '_map_model_to_entity') as mock_map:
            mock_map.return_value = sample_auth_token

            result = await token_repository.update_token(sample_auth_token)

            assert result == sample_auth_token
            mock_session.flush.assert_called_once()


