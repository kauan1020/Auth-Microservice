import pytest
from unittest.mock import Mock, AsyncMock
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional

from domain.entities.auth_token import AuthToken, TokenType
from domain.exceptions import InvalidTokenException, TokenExpiredException


@dataclass
class ValidateTokenRequest:
    """Request data structure for token validation use case."""
    token: str


@dataclass
class ValidateTokenResponse:
    """Response data structure for token validation use case."""
    valid: bool
    user_id: Optional[str] = None
    token_type: Optional[str] = None
    expires_at: Optional[str] = None
    issued_at: Optional[str] = None
    reason: Optional[str] = None


class ValidateTokenUseCase:
    """Use case for handling token validation operations."""

    def __init__(self, token_repository, jwt_service):
        self.token_repository = token_repository
        self.jwt_service = jwt_service

    async def execute(self, request: ValidateTokenRequest) -> ValidateTokenResponse:
        """Execute the token validation use case."""
        try:
            payload = self.jwt_service.decode_token(request.token)

            stored_token = await self.token_repository.find_by_token(request.token)

            if not stored_token:
                return ValidateTokenResponse(
                    valid=False,
                    reason="Token not found in database"
                )

            if stored_token.is_revoked:
                return ValidateTokenResponse(
                    valid=False,
                    reason="Token has been revoked"
                )

            if not stored_token.is_valid():
                return ValidateTokenResponse(
                    valid=False,
                    reason="Token is expired"
                )

            return ValidateTokenResponse(
                valid=True,
                user_id=payload.get("sub"),
                token_type=payload.get("type"),
                expires_at=stored_token.expires_at.isoformat() if stored_token.expires_at else None,
                issued_at=stored_token.created_at.isoformat() if stored_token.created_at else None
            )

        except TokenExpiredException:
            return ValidateTokenResponse(
                valid=False,
                reason="Token has expired"
            )
        except InvalidTokenException as e:
            return ValidateTokenResponse(
                valid=False,
                reason=str(e)
            )
        except Exception as e:
            return ValidateTokenResponse(
                valid=False,
                reason=f"Token validation failed: {str(e)}"
            )


class TestValidateTokenUseCase:

    @pytest.fixture
    def token_repository(self):
        return AsyncMock()

    @pytest.fixture
    def jwt_service(self):
        mock = Mock()
        mock.decode_token.return_value = {
            "sub": "user-123",
            "type": "access",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        return mock

    @pytest.fixture
    def validate_token_use_case(self, token_repository, jwt_service):
        return ValidateTokenUseCase(token_repository, jwt_service)

    @pytest.fixture
    def valid_stored_token(self):
        return AuthToken(
            token="valid_token",
            token_type=TokenType.ACCESS,
            user_id="user-123",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            created_at=datetime.utcnow(),
            is_revoked=False
        )

    @pytest.fixture
    def revoked_stored_token(self):
        return AuthToken(
            token="revoked_token",
            token_type=TokenType.ACCESS,
            user_id="user-123",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            created_at=datetime.utcnow(),
            is_revoked=True
        )

    @pytest.fixture
    def expired_stored_token(self):
        return AuthToken(
            token="expired_token",
            token_type=TokenType.ACCESS,
            user_id="user-123",
            expires_at=datetime.utcnow() - timedelta(hours=1),
            created_at=datetime.utcnow() - timedelta(hours=2),
            is_revoked=False
        )

    async def test_execute_returns_valid_true_when_token_is_valid(self, validate_token_use_case, token_repository,
                                                                  jwt_service, valid_stored_token):
        token_repository.find_by_token.return_value = valid_stored_token
        request = ValidateTokenRequest(token="valid_token")

        result = await validate_token_use_case.execute(request)

        assert result.valid is True
        assert result.user_id == "user-123"
        assert result.token_type == "access"
        assert result.expires_at is not None
        assert result.issued_at is not None
        assert result.reason is None

    async def test_execute_returns_valid_false_when_token_not_found_in_database(self, validate_token_use_case,
                                                                                token_repository, jwt_service):
        token_repository.find_by_token.return_value = None
        request = ValidateTokenRequest(token="nonexistent_token")

        result = await validate_token_use_case.execute(request)

        assert result.valid is False
        assert result.reason == "Token not found in database"

    async def test_execute_returns_valid_false_when_token_is_revoked(self, validate_token_use_case, token_repository,
                                                                     jwt_service, revoked_stored_token):
        token_repository.find_by_token.return_value = revoked_stored_token
        request = ValidateTokenRequest(token="revoked_token")

        result = await validate_token_use_case.execute(request)

        assert result.valid is False
        assert result.reason == "Token has been revoked"

    async def test_execute_returns_valid_false_when_token_is_expired(self, validate_token_use_case, token_repository,
                                                                     jwt_service, expired_stored_token):
        token_repository.find_by_token.return_value = expired_stored_token
        request = ValidateTokenRequest(token="expired_token")

        result = await validate_token_use_case.execute(request)

        assert result.valid is False
        assert result.reason == "Token is expired"

    async def test_execute_returns_valid_false_when_jwt_decode_raises_token_expired_exception(self,
                                                                                              validate_token_use_case,
                                                                                              token_repository,
                                                                                              jwt_service):
        jwt_service.decode_token.side_effect = TokenExpiredException()
        request = ValidateTokenRequest(token="expired_jwt_token")

        result = await validate_token_use_case.execute(request)

        assert result.valid is False
        assert result.reason == "Token has expired"

    async def test_execute_returns_valid_false_when_unexpected_exception_occurs(self, validate_token_use_case,
                                                                                token_repository, jwt_service):
        jwt_service.decode_token.side_effect = Exception("Unexpected error")
        request = ValidateTokenRequest(token="problematic_token")

        result = await validate_token_use_case.execute(request)

        assert result.valid is False
        assert "Token validation failed" in result.reason
        assert "Unexpected error" in result.reason

    async def test_execute_calls_jwt_service_decode_token_with_correct_token(self, validate_token_use_case,
                                                                             token_repository, jwt_service,
                                                                             valid_stored_token):
        token_repository.find_by_token.return_value = valid_stored_token
        request = ValidateTokenRequest(token="test_token")

        await validate_token_use_case.execute(request)

        jwt_service.decode_token.assert_called_once_with("test_token")

    async def test_execute_calls_token_repository_find_by_token_with_correct_token(self, validate_token_use_case,
                                                                                   token_repository, jwt_service,
                                                                                   valid_stored_token):
        token_repository.find_by_token.return_value = valid_stored_token
        request = ValidateTokenRequest(token="test_token")

        await validate_token_use_case.execute(request)

        token_repository.find_by_token.assert_called_once_with("test_token")