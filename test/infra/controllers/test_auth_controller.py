import pytest
from unittest.mock import AsyncMock, Mock, patch
from fastapi import Request, Response
import json

from infra.controllers.auth_controller import AuthController
from domain.exceptions import (
    UserAlreadyExistsException,
    WeakPasswordException,
    InvalidCredentialsException,
    AuthenticationException,
    InvalidTokenException,
    TokenExpiredException
)


class TestAuthController:

    @pytest.fixture
    def mock_register_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_login_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_logout_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_refresh_token_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_validate_token_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_presenter(self):
        mock = Mock()
        mock.present_registration_success.return_value = {"success": True}
        mock.present_login_success.return_value = {"success": True}
        mock.present_logout_success.return_value = {"success": True}
        mock.present_token_refresh_success.return_value = {"success": True}
        mock.present_token_validation_success.return_value = {"success": True}
        mock.present_authentication_error.return_value = {"success": False}
        mock.present_validation_error.return_value = {"success": False}
        mock.present_server_error.return_value = {"success": False}
        return mock

    @pytest.fixture
    def auth_controller(self, mock_register_use_case, mock_login_use_case, mock_logout_use_case,
                        mock_refresh_token_use_case, mock_validate_token_use_case, mock_presenter):
        return AuthController(
            register_use_case=mock_register_use_case,
            login_use_case=mock_login_use_case,
            logout_use_case=mock_logout_use_case,
            refresh_token_use_case=mock_refresh_token_use_case,
            validate_token_use_case=mock_validate_token_use_case,
            presenter=mock_presenter
        )

    @pytest.fixture
    def mock_request(self):
        request = AsyncMock(spec=Request)
        request.json = AsyncMock()
        request.headers = {}
        return request

    async def test_register_returns_success_response_when_registration_succeeds(self, auth_controller,
                                                                                mock_register_use_case, mock_presenter,
                                                                                mock_request):
        mock_request.json.return_value = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "password123",
            "first_name": "John",
            "last_name": "Doe"
        }

        mock_result = Mock()
        mock_result.user_data = {"id": "user-123", "email": "test@example.com"}
        mock_register_use_case.execute.return_value = mock_result

        response = await auth_controller.register(mock_request)

        assert response.status_code == 201
        assert response.media_type == "application/json"
        mock_register_use_case.execute.assert_called_once()
        mock_presenter.present_registration_success.assert_called_once()

    async def test_register_returns_conflict_response_when_user_already_exists(self, auth_controller,
                                                                               mock_register_use_case, mock_presenter,
                                                                               mock_request):
        mock_request.json.return_value = {"email": "test@example.com"}
        mock_register_use_case.execute.side_effect = UserAlreadyExistsException("email", "test@example.com")

        response = await auth_controller.register(mock_request)

        assert response.status_code == 409
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_register_returns_bad_request_response_when_password_is_weak(self, auth_controller,
                                                                               mock_register_use_case, mock_presenter,
                                                                               mock_request):
        mock_request.json.return_value = {"email": "test@example.com"}
        mock_register_use_case.execute.side_effect = WeakPasswordException("Password too weak")

        response = await auth_controller.register(mock_request)

        assert response.status_code == 400
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_register_returns_bad_request_response_when_validation_fails(self, auth_controller,
                                                                               mock_register_use_case, mock_presenter,
                                                                               mock_request):
        mock_request.json.return_value = {"email": "test@example.com"}
        mock_register_use_case.execute.side_effect = ValueError("Invalid data")

        response = await auth_controller.register(mock_request)

        assert response.status_code == 400
        mock_presenter.present_validation_error.assert_called_once()

    async def test_register_returns_server_error_response_when_unexpected_error_occurs(self, auth_controller,
                                                                                       mock_register_use_case,
                                                                                       mock_presenter, mock_request):
        mock_request.json.return_value = {"email": "test@example.com"}
        mock_register_use_case.execute.side_effect = Exception("Unexpected error")

        response = await auth_controller.register(mock_request)

        assert response.status_code == 500
        mock_presenter.present_server_error.assert_called_once()

    async def test_login_returns_success_response_when_authentication_succeeds(self, auth_controller,
                                                                               mock_login_use_case, mock_presenter,
                                                                               mock_request):
        mock_request.json.return_value = {
            "identifier": "test@example.com",
            "password": "password123",
            "remember_me": False
        }

        mock_result = Mock()
        mock_result.access_token = "access_token"
        mock_result.refresh_token = "refresh_token"
        mock_result.token_type = "Bearer"
        mock_result.expires_in = 900
        mock_result.user_data = {"id": "user-123"}
        mock_login_use_case.execute.return_value = mock_result

        response = await auth_controller.login(mock_request)

        assert response.status_code == 200
        mock_login_use_case.execute.assert_called_once()
        mock_presenter.present_login_success.assert_called_once()

    async def test_login_returns_unauthorized_response_when_credentials_invalid(self, auth_controller,
                                                                                mock_login_use_case, mock_presenter,
                                                                                mock_request):
        mock_request.json.return_value = {"identifier": "test@example.com"}
        mock_login_use_case.execute.side_effect = InvalidCredentialsException()

        response = await auth_controller.login(mock_request)

        assert response.status_code == 401
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_login_returns_unauthorized_response_when_authentication_fails(self, auth_controller,
                                                                                 mock_login_use_case, mock_presenter,
                                                                                 mock_request):
        mock_request.json.return_value = {"identifier": "test@example.com"}
        mock_login_use_case.execute.side_effect = AuthenticationException("Auth failed")

        response = await auth_controller.login(mock_request)

        assert response.status_code == 401
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_logout_returns_success_response_when_logout_succeeds(self, auth_controller, mock_logout_use_case,
                                                                        mock_presenter, mock_request):
        mock_request.headers = {"Authorization": "Bearer valid_token"}
        mock_request.json.return_value = {}
        mock_request.method = "POST"

        mock_result = Mock()
        mock_logout_use_case.execute.return_value = mock_result

        response = await auth_controller.logout(mock_request)

        assert response.status_code == 200
        mock_logout_use_case.execute.assert_called_once()
        mock_presenter.present_logout_success.assert_called_once()

    async def test_logout_returns_unauthorized_response_when_authorization_header_missing(self, auth_controller,
                                                                                          mock_presenter, mock_request):
        mock_request.headers = {}

        response = await auth_controller.logout(mock_request)

        assert response.status_code == 401
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_logout_returns_unauthorized_response_when_token_invalid(self, auth_controller, mock_logout_use_case,
                                                                           mock_presenter, mock_request):
        mock_request.headers = {"Authorization": "Bearer invalid_token"}
        mock_request.json.return_value = {}
        mock_request.method = "POST"
        mock_logout_use_case.execute.side_effect = InvalidTokenException("Invalid token")

        response = await auth_controller.logout(mock_request)

        assert response.status_code == 401
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_refresh_token_returns_success_response_when_refresh_succeeds(self, auth_controller,
                                                                                mock_refresh_token_use_case,
                                                                                mock_presenter, mock_request):
        mock_request.json.return_value = {"refresh_token": "valid_refresh_token"}

        mock_result = Mock()
        mock_result.access_token = "new_access_token"
        mock_result.token_type = "Bearer"
        mock_result.expires_in = 900
        mock_refresh_token_use_case.execute.return_value = mock_result

        response = await auth_controller.refresh_token(mock_request)

        assert response.status_code == 200
        mock_refresh_token_use_case.execute.assert_called_once()
        mock_presenter.present_token_refresh_success.assert_called_once()

    async def test_refresh_token_returns_unauthorized_response_when_token_expired(self, auth_controller,
                                                                                  mock_refresh_token_use_case,
                                                                                  mock_presenter, mock_request):
        mock_request.json.return_value = {"refresh_token": "expired_token"}
        mock_refresh_token_use_case.execute.side_effect = TokenExpiredException()

        response = await auth_controller.refresh_token(mock_request)

        assert response.status_code == 401
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_refresh_token_returns_unauthorized_response_when_token_invalid(self, auth_controller,
                                                                                  mock_refresh_token_use_case,
                                                                                  mock_presenter, mock_request):
        mock_request.json.return_value = {"refresh_token": "invalid_token"}
        mock_refresh_token_use_case.execute.side_effect = InvalidTokenException("Invalid token")

        response = await auth_controller.refresh_token(mock_request)

        assert response.status_code == 401
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_validate_token_returns_success_response_when_token_valid_from_header(self, auth_controller,
                                                                                        mock_validate_token_use_case,
                                                                                        mock_presenter, mock_request):
        mock_request.headers = {"Authorization": "Bearer valid_token"}

        mock_result = Mock()
        mock_result.valid = True
        mock_result.user_id = "user-123"
        mock_result.token_type = "access"
        mock_result.expires_at = "2023-12-31T23:59:59"
        mock_result.issued_at = "2023-12-31T12:00:00"
        mock_validate_token_use_case.execute.return_value = mock_result

        response = await auth_controller.validate_token(mock_request)

        assert response.status_code == 200
        mock_validate_token_use_case.execute.assert_called_once()
        mock_presenter.present_token_validation_success.assert_called_once()

    async def test_validate_token_returns_success_response_when_token_valid_from_body(self, auth_controller,
                                                                                      mock_validate_token_use_case,
                                                                                      mock_presenter, mock_request):
        mock_request.headers = {}
        mock_request.json.return_value = {"token": "valid_token"}

        mock_result = Mock()
        mock_result.valid = True
        mock_result.user_id = "user-123"
        mock_result.token_type = "access"
        mock_result.expires_at = "2023-12-31T23:59:59"
        mock_result.issued_at = "2023-12-31T12:00:00"
        mock_validate_token_use_case.execute.return_value = mock_result

        response = await auth_controller.validate_token(mock_request)

        assert response.status_code == 200

    async def test_validate_token_returns_bad_request_response_when_no_token_provided(self, auth_controller,
                                                                                      mock_presenter, mock_request):
        mock_request.headers = {}
        mock_request.json.return_value = {}

        response = await auth_controller.validate_token(mock_request)

        assert response.status_code == 400
        mock_presenter.present_authentication_error.assert_called_once()

    async def test_validate_token_returns_server_error_response_when_unexpected_error_occurs(self, auth_controller,
                                                                                             mock_validate_token_use_case,
                                                                                             mock_presenter,
                                                                                             mock_request):
        mock_request.headers = {"Authorization": "Bearer valid_token"}
        mock_validate_token_use_case.execute.side_effect = Exception("Unexpected error")

        response = await auth_controller.validate_token(mock_request)

        assert response.status_code == 500
        mock_presenter.present_server_error.assert_called_once()

    def test_serialize_response_returns_formatted_json_string(self, auth_controller):
        data = {"success": True, "message": "Test"}

        result = auth_controller._serialize_response(data)

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["success"] is True
        assert parsed["message"] == "Test"