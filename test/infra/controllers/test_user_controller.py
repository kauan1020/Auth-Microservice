import pytest
from unittest.mock import AsyncMock, Mock, patch
from fastapi import Request, Response
import json

from infra.controllers.user_controller import UserController
from domain.exceptions import (
    UserAlreadyExistsException,
    WeakPasswordException,
    InvalidCredentialsException,
    UserNotFoundException,
    InvalidTokenException,
)


class TestUserController:

    @pytest.fixture
    def mock_get_user_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_update_user_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_change_password_use_case(self):
        return AsyncMock()

    @pytest.fixture
    def mock_jwt_service(self):
        mock = Mock()
        mock.extract_user_id.return_value = "user-123"
        return mock

    @pytest.fixture
    def mock_presenter(self):
        mock = Mock()
        mock.present_user_profile.return_value = {"success": True}
        mock.present_profile_update_success.return_value = {"success": True}
        mock.present_password_change_success.return_value = {"success": True}
        mock.present_unauthorized_access.return_value = {"success": False}
        mock.present_user_not_found.return_value = {"success": False}
        mock.present_user_already_exists.return_value = {"success": False}
        mock.present_validation_error.return_value = {"success": False}
        mock.present_password_validation_error.return_value = {"success": False}
        mock.present_server_error.return_value = {"success": False}
        return mock

    @pytest.fixture
    def user_controller(self, mock_get_user_use_case, mock_update_user_use_case, mock_change_password_use_case,
                        mock_jwt_service, mock_presenter):
        return UserController(
            get_user_use_case=mock_get_user_use_case,
            update_user_use_case=mock_update_user_use_case,
            change_password_use_case=mock_change_password_use_case,
            jwt_service=mock_jwt_service,
            presenter=mock_presenter
        )

    @pytest.fixture
    def mock_request(self):
        request = AsyncMock(spec=Request)
        request.json = AsyncMock()
        request.headers = {"Authorization": "Bearer valid_token"}
        return request

    async def test_get_user_profile_returns_success_response_when_user_exists(self, user_controller,
                                                                              mock_get_user_use_case, mock_presenter,
                                                                              mock_request):
        mock_result = Mock()
        mock_result.user_data = {"id": "user-123", "email": "test@example.com"}
        mock_get_user_use_case.execute.return_value = mock_result

        response = await user_controller.get_user_profile(mock_request)

        assert response.status_code == 200
        mock_get_user_use_case.execute.assert_called_once()
        mock_presenter.present_user_profile.assert_called_once()

    async def test_get_user_profile_returns_unauthorized_response_when_token_invalid(self, user_controller,
                                                                                     mock_jwt_service, mock_presenter,
                                                                                     mock_request):
        mock_jwt_service.extract_user_id.side_effect = InvalidTokenException("Invalid token")

        response = await user_controller.get_user_profile(mock_request)

        assert response.status_code == 401
        mock_presenter.present_unauthorized_access.assert_called_once()

    async def test_get_user_profile_returns_not_found_response_when_user_not_found(self, user_controller,
                                                                                   mock_get_user_use_case,
                                                                                   mock_presenter, mock_request):
        mock_get_user_use_case.execute.side_effect = UserNotFoundException("user-123")

        response = await user_controller.get_user_profile(mock_request)

        assert response.status_code == 404
        mock_presenter.present_user_not_found.assert_called_once()

    async def test_get_user_profile_returns_server_error_response_when_unexpected_error_occurs(self, user_controller,
                                                                                               mock_get_user_use_case,
                                                                                               mock_presenter,
                                                                                               mock_request):
        mock_get_user_use_case.execute.side_effect = Exception("Unexpected error")

        response = await user_controller.get_user_profile(mock_request)

        assert response.status_code == 500
        mock_presenter.present_server_error.assert_called_once()

    async def test_update_user_profile_returns_success_response_when_update_succeeds(self, user_controller,
                                                                                     mock_update_user_use_case,
                                                                                     mock_presenter, mock_request):
        mock_request.json.return_value = {
            "first_name": "John",
            "last_name": "Doe",
            "username": "johndoe"
        }

        mock_result = Mock()
        mock_result.user_data = {"id": "user-123", "first_name": "John"}
        mock_update_user_use_case.execute.return_value = mock_result

        response = await user_controller.update_user_profile(mock_request)

        assert response.status_code == 200
        mock_update_user_use_case.execute.assert_called_once()
        mock_presenter.present_profile_update_success.assert_called_once()

    async def test_update_user_profile_returns_unauthorized_response_when_token_invalid(self, user_controller,
                                                                                        mock_jwt_service,
                                                                                        mock_presenter, mock_request):
        mock_jwt_service.extract_user_id.side_effect = InvalidTokenException("Invalid token")

        response = await user_controller.update_user_profile(mock_request)

        assert response.status_code == 401
        mock_presenter.present_unauthorized_access.assert_called_once()

    async def test_update_user_profile_returns_not_found_response_when_user_not_found(self, user_controller,
                                                                                      mock_update_user_use_case,
                                                                                      mock_presenter, mock_request):
        mock_request.json.return_value = {"first_name": "John"}
        mock_update_user_use_case.execute.side_effect = UserNotFoundException("user-123")

        response = await user_controller.update_user_profile(mock_request)

        assert response.status_code == 404
        mock_presenter.present_user_not_found.assert_called_once()

    async def test_update_user_profile_returns_conflict_response_when_user_already_exists(self, user_controller,
                                                                                          mock_update_user_use_case,
                                                                                          mock_presenter, mock_request):
        mock_request.json.return_value = {"username": "existinguser"}
        mock_update_user_use_case.execute.side_effect = UserAlreadyExistsException("username", "existinguser")

        response = await user_controller.update_user_profile(mock_request)

        assert response.status_code == 409
        mock_presenter.present_user_already_exists.assert_called_once()

    async def test_update_user_profile_returns_bad_request_response_when_validation_fails(self, user_controller,
                                                                                          mock_update_user_use_case,
                                                                                          mock_presenter, mock_request):
        mock_request.json.return_value = {"first_name": ""}
        mock_update_user_use_case.execute.side_effect = ValueError("Invalid data")

        response = await user_controller.update_user_profile(mock_request)

        assert response.status_code == 400
        mock_presenter.present_validation_error.assert_called_once()

    async def test_change_password_returns_success_response_when_password_change_succeeds(self, user_controller,
                                                                                          mock_change_password_use_case,
                                                                                          mock_presenter, mock_request):
        mock_request.json.return_value = {
            "current_password": "old_password",
            "new_password": "new_password",
            "confirm_password": "new_password"
        }

        mock_result = Mock()
        mock_change_password_use_case.execute.return_value = mock_result

        response = await user_controller.change_password(mock_request)

        assert response.status_code == 200
        mock_change_password_use_case.execute.assert_called_once()
        mock_presenter.present_password_change_success.assert_called_once()

    async def test_change_password_returns_bad_request_response_when_passwords_dont_match(self, user_controller,
                                                                                          mock_presenter, mock_request):
        mock_request.json.return_value = {
            "current_password": "old_password",
            "new_password": "new_password",
            "confirm_password": "different_password"
        }

        response = await user_controller.change_password(mock_request)

        assert response.status_code == 400
        mock_presenter.present_validation_error.assert_called_once()

    async def test_change_password_returns_unauthorized_response_when_token_invalid(self, user_controller,
                                                                                    mock_jwt_service, mock_presenter,
                                                                                    mock_request):
        mock_jwt_service.extract_user_id.side_effect = InvalidTokenException("Invalid token")

        response = await user_controller.change_password(mock_request)

        assert response.status_code == 401
        mock_presenter.present_unauthorized_access.assert_called_once()

    async def test_change_password_returns_not_found_response_when_user_not_found(self, user_controller,
                                                                                  mock_change_password_use_case,
                                                                                  mock_presenter, mock_request):
        mock_request.json.return_value = {
            "current_password": "old_password",
            "new_password": "new_password",
            "confirm_password": "new_password"
        }
        mock_change_password_use_case.execute.side_effect = UserNotFoundException("user-123")

        response = await user_controller.change_password(mock_request)

        assert response.status_code == 404
        mock_presenter.present_user_not_found.assert_called_once()

    async def test_change_password_returns_bad_request_response_when_current_password_invalid(self, user_controller,
                                                                                              mock_change_password_use_case,
                                                                                              mock_presenter,
                                                                                              mock_request):
        mock_request.json.return_value = {
            "current_password": "wrong_password",
            "new_password": "new_password",
            "confirm_password": "new_password"
        }
        mock_change_password_use_case.execute.side_effect = InvalidCredentialsException()

        response = await user_controller.change_password(mock_request)

        assert response.status_code == 400
        mock_presenter.present_validation_error.assert_called_once()

    async def test_change_password_returns_bad_request_response_when_new_password_weak(self, user_controller,
                                                                                       mock_change_password_use_case,
                                                                                       mock_presenter, mock_request):
        mock_request.json.return_value = {
            "current_password": "old_password",
            "new_password": "weak",
            "confirm_password": "weak"
        }
        mock_change_password_use_case.execute.side_effect = WeakPasswordException("Password too weak")

        response = await user_controller.change_password(mock_request)

        assert response.status_code == 400
        mock_presenter.present_password_validation_error.assert_called_once()

    async def test_deactivate_user_returns_not_implemented_response(self, user_controller, mock_request):
        response = await user_controller.deactivate_user(mock_request)

        assert response.status_code == 501
        response_data = json.loads(response.body)
        assert response_data["success"] is True
        assert "not implemented" in response_data["message"]

    async def test_deactivate_user_returns_unauthorized_response_when_token_invalid(self, user_controller,
                                                                                    mock_jwt_service, mock_presenter,
                                                                                    mock_request):
        mock_jwt_service.extract_user_id.side_effect = InvalidTokenException("Invalid token")

        response = await user_controller.deactivate_user(mock_request)

        assert response.status_code == 401
        mock_presenter.present_unauthorized_access.assert_called_once()

    async def test_extract_user_id_from_token_returns_user_id_when_token_valid(self, user_controller, mock_jwt_service,
                                                                               mock_request):
        user_id = await user_controller._extract_user_id_from_token(mock_request)

        assert user_id == "user-123"
        mock_jwt_service.extract_user_id.assert_called_once_with("valid_token")

    async def test_extract_user_id_from_token_raises_exception_when_header_missing(self, user_controller, mock_request):
        mock_request.headers = {}

        with pytest.raises(InvalidTokenException):
            await user_controller._extract_user_id_from_token(mock_request)

    async def test_extract_user_id_from_token_raises_exception_when_header_invalid(self, user_controller, mock_request):
        mock_request.headers = {"Authorization": "InvalidHeader"}

        with pytest.raises(InvalidTokenException):
            await user_controller._extract_user_id_from_token(mock_request)

    def test_serialize_response_returns_formatted_json_string(self, user_controller):
        data = {"success": True, "message": "Test"}

        result = user_controller._serialize_response(data)

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["success"] is True
        assert parsed["message"] == "Test"