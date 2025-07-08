import pytest
from unittest.mock import AsyncMock, Mock
from domain.exceptions import (
    InvalidTokenException,
)


from use_cases.authenticate.logout_use_case import LogoutUseCase, LogoutRequest, LogoutResponse

class TestLogoutUseCase:

    @pytest.fixture
    def token_repository(self):
        return AsyncMock()

    @pytest.fixture
    def jwt_service(self):
        mock = Mock()
        mock.extract_user_id.return_value = "user-123"
        return mock

    @pytest.fixture
    def logout_use_case(self, token_repository, jwt_service):
        return LogoutUseCase(token_repository, jwt_service)

    async def test_execute_successfully_revokes_single_token(self, logout_use_case, token_repository, jwt_service):
        token_repository.revoke_token.return_value = True

        request = LogoutRequest(
            access_token="valid_token",
            revoke_all=False
        )

        result = await logout_use_case.execute(request)

        assert result.success is True
        assert result.tokens_revoked == 1
        assert "current session" in result.message

    async def test_execute_successfully_revokes_all_tokens(self, logout_use_case, token_repository, jwt_service):
        token_repository.revoke_all_user_tokens.return_value = 3

        request = LogoutRequest(
            access_token="valid_token",
            revoke_all=True
        )

        result = await logout_use_case.execute(request)

        assert result.success is True
        assert result.tokens_revoked == 3
        assert "all devices" in result.message

    async def test_execute_raises_invalid_token_exception_when_token_invalid(self, logout_use_case, jwt_service):
        jwt_service.extract_user_id.side_effect = Exception("Invalid token")

        request = LogoutRequest(
            access_token="invalid_token",
            revoke_all=False
        )

        with pytest.raises(InvalidTokenException):
            await logout_use_case.execute(request)

    async def test_execute_handles_no_tokens_revoked_gracefully(self, logout_use_case, token_repository, jwt_service):
        token_repository.revoke_token.return_value = False

        request = LogoutRequest(
            access_token="valid_token",
            revoke_all=False
        )

        result = await logout_use_case.execute(request)

        assert result.success is True
        assert result.tokens_revoked == 0
        assert "already terminated" in result.message
