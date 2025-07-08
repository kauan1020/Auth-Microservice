import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import jwt


from infra.security.jwt_service import JWTService
from domain.entities.auth_token import AuthToken, TokenType
from domain.exceptions import InvalidTokenException


class TestJWTService:

    @pytest.fixture
    def jwt_service(self):
        return JWTService(
            secret_key="test_secret_key",
            algorithm="HS256",
            issuer="test_issuer"
        )

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

    def test_generate_token_returns_valid_jwt_token(self, jwt_service, sample_auth_token):
        claims = {"username": "testuser", "email": "test@example.com"}

        token = jwt_service.generate_token(sample_auth_token, claims)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_raises_exception_when_signing_fails(self, jwt_service, sample_auth_token):
        with patch('jwt.encode') as mock_encode:
            mock_encode.side_effect = Exception("Signing failed")

            with pytest.raises(InvalidTokenException):
                jwt_service.generate_token(sample_auth_token, {})

    def test_decode_token_raises_invalid_token_exception_when_token_malformed(self, jwt_service):
        with pytest.raises(InvalidTokenException):
            jwt_service.decode_token("invalid_token")

    def test_decode_token_raises_invalid_token_exception_when_wrong_issuer(self, jwt_service):
        payload = {
            "iss": "wrong_issuer",
            "sub": "user-123",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        with pytest.raises(InvalidTokenException):
            jwt_service.decode_token(token)

    def test_extract_user_id_returns_correct_user_id(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        user_id = jwt_service.extract_user_id(token)

        assert user_id == "user-123"

    def test_extract_user_id_raises_exception_when_user_id_missing(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        with pytest.raises(InvalidTokenException):
            jwt_service.extract_user_id(token)

    def test_extract_token_type_returns_correct_token_type(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "type": "access",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        token_type = jwt_service.extract_token_type(token)

        assert token_type == "access"

    def test_extract_token_type_raises_exception_when_type_missing(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        with pytest.raises(InvalidTokenException):
            jwt_service.extract_token_type(token)

    def test_is_token_expired_returns_false_when_token_valid(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        is_expired = jwt_service.is_token_expired(token)

        assert is_expired is False

    def test_is_token_expired_returns_true_when_token_invalid(self, jwt_service):
        is_expired = jwt_service.is_token_expired("invalid_token")

        assert is_expired is True

    def test_get_token_expiration_returns_correct_timestamp(self, jwt_service):
        exp_time = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "exp": exp_time
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        expiration = jwt_service.get_token_expiration(token)

        assert expiration == exp_time

    def test_get_token_expiration_returns_none_when_token_invalid(self, jwt_service):
        expiration = jwt_service.get_token_expiration("invalid_token")

        assert expiration is None

    def test_refresh_token_claims_returns_correct_claims(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "type": "refresh",
            "username": "testuser",
            "email": "test@example.com",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        claims = jwt_service.refresh_token_claims(token)

        assert claims["username"] == "testuser"
        assert claims["email"] == "test@example.com"

    def test_refresh_token_claims_raises_exception_when_not_refresh_token(self, jwt_service):
        payload = {
            "iss": "test_issuer",
            "sub": "user-123",
            "type": "access",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "test_secret_key", algorithm="HS256")

        with pytest.raises(InvalidTokenException):
            jwt_service.refresh_token_claims(token)

    def test_create_token_claims_returns_correct_claims(self, jwt_service):
        additional_claims = {"username": "testuser", "email": "test@example.com"}

        claims = jwt_service.create_token_claims("user-123", "access", additional_claims)

        assert claims["user_id"] == "user-123"
        assert claims["token_type"] == "access"
        assert claims["username"] == "testuser"
        assert claims["email"] == "test@example.com"

    def test_create_token_claims_works_without_additional_claims(self, jwt_service):
        claims = jwt_service.create_token_claims("user-123", "access")

        assert claims["user_id"] == "user-123"
        assert claims["token_type"] == "access"
        assert len(claims) == 2

