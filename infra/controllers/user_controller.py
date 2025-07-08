from fastapi import Request, Response, status
from typing import Dict, Any
import logging

from interfaces.controllers.user_controller import UserControllerInterface
from interfaces.presenters.user_presenter import UserPresenterInterface
from interfaces.services.jwt_service import JWTServiceInterface
from use_cases.users.get_user_use_case import GetUserUseCase, GetUserRequest
from use_cases.users.update_user_use_case import UpdateUserUseCase, UpdateUserRequest
from use_cases.users.change_password_use_case import ChangePasswordUseCase, ChangePasswordRequest
from domain.exceptions import (
    UserNotFoundException,
    UserAlreadyExistsException,
    InvalidCredentialsException,
    WeakPasswordException,
    InvalidTokenException
)

logger = logging.getLogger(__name__)


class UserController(UserControllerInterface):
    """
    Implementation of user management controller for HTTP request handling.

    This controller handles all user-related HTTP requests including profile
    management, password changes, and user operations while maintaining
    proper authentication and authorization.

    It coordinates between use cases and presenters to provide consistent
    API responses and handles various error scenarios appropriately.
    """

    def __init__(self,
                 get_user_use_case: GetUserUseCase,
                 update_user_use_case: UpdateUserUseCase,
                 change_password_use_case: ChangePasswordUseCase,
                 jwt_service: JWTServiceInterface,
                 presenter: UserPresenterInterface):
        """
        Initialize the user controller.

        Args:
            get_user_use_case: Use case for retrieving user information
            update_user_use_case: Use case for updating user profile
            change_password_use_case: Use case for changing user password
            jwt_service: Service for JWT token operations
            presenter: Presenter for formatting responses
        """
        self.get_user_use_case = get_user_use_case
        self.update_user_use_case = update_user_use_case
        self.change_password_use_case = change_password_use_case
        self.jwt_service = jwt_service
        self.presenter = presenter

    async def get_user_profile(self, request: Request) -> Response:
        """
        Get user profile information.

        Args:
            request: FastAPI request object with authentication header

        Returns:
            Response: HTTP response with user profile data
        """
        try:
            user_id = await self._extract_user_id_from_token(request)

            get_user_request = GetUserRequest(user_id=user_id)
            result = await self.get_user_use_case.execute(get_user_request)

            response_data = self.presenter.present_user_profile(result.user_data)

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_200_OK,
                media_type="application/json"
            )

        except InvalidTokenException as e:
            logger.warning(f"Get profile failed - invalid token: {e.message}")
            response_data = self.presenter.present_unauthorized_access()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except UserNotFoundException as e:
            logger.warning(f"Get profile failed - user not found: {e.message}")
            response_data = self.presenter.present_user_not_found()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_404_NOT_FOUND,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Get profile failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def update_user_profile(self, request: Request) -> Response:
        """
        Update user profile information.

        Args:
            request: FastAPI request object with profile update data

        Returns:
            Response: HTTP response with updated profile data
        """
        try:
            user_id = await self._extract_user_id_from_token(request)
            request_data = await request.json()

            update_request = UpdateUserRequest(
                user_id=user_id,
                first_name=request_data.get("first_name"),
                last_name=request_data.get("last_name"),
                username=request_data.get("username")
            )

            result = await self.update_user_use_case.execute(update_request)
            response_data = self.presenter.present_profile_update_success(result.user_data)

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_200_OK,
                media_type="application/json"
            )

        except InvalidTokenException as e:
            logger.warning(f"Update profile failed - invalid token: {e.message}")
            response_data = self.presenter.present_unauthorized_access()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except UserNotFoundException as e:
            logger.warning(f"Update profile failed - user not found: {e.message}")
            response_data = self.presenter.present_user_not_found()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_404_NOT_FOUND,
                media_type="application/json"
            )

        except UserAlreadyExistsException as e:
            logger.warning(f"Update profile failed - user exists: {e.message}")
            field = "username" if "username" in e.message else "email"
            response_data = self.presenter.present_user_already_exists(field, "")
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_409_CONFLICT,
                media_type="application/json"
            )

        except ValueError as e:
            logger.warning(f"Update profile failed - validation error: {str(e)}")
            response_data = self.presenter.present_validation_error({"general": [str(e)]})
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Update profile failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def change_password(self, request: Request) -> Response:
        """
        Handle password change request.

        Args:
            request: FastAPI request object with password change data

        Returns:
            Response: HTTP response with password change result
        """
        try:
            user_id = await self._extract_user_id_from_token(request)
            request_data = await request.json()

            current_password = request_data.get("current_password")
            new_password = request_data.get("new_password")
            confirm_password = request_data.get("confirm_password")

            if new_password != confirm_password:
                response_data = self.presenter.present_validation_error({
                    "confirm_password": ["Password confirmation does not match"]
                })
                return Response(
                    content=self._serialize_response(response_data),
                    status_code=status.HTTP_400_BAD_REQUEST,
                    media_type="application/json"
                )

            change_password_request = ChangePasswordRequest(
                user_id=user_id,
                current_password=current_password,
                new_password=new_password
            )

            result = await self.change_password_use_case.execute(change_password_request)
            response_data = self.presenter.present_password_change_success()

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_200_OK,
                media_type="application/json"
            )

        except InvalidTokenException as e:
            logger.warning(f"Change password failed - invalid token: {e.message}")
            response_data = self.presenter.present_unauthorized_access()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except UserNotFoundException as e:
            logger.warning(f"Change password failed - user not found: {e.message}")
            response_data = self.presenter.present_user_not_found()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_404_NOT_FOUND,
                media_type="application/json"
            )

        except InvalidCredentialsException as e:
            logger.warning(f"Change password failed - invalid current password: {e.message}")
            response_data = self.presenter.present_validation_error({
                "current_password": ["Current password is incorrect"]
            })
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="application/json"
            )

        except WeakPasswordException as e:
            logger.warning(f"Change password failed - weak password: {e.message}")
            response_data = self.presenter.present_password_validation_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Change password failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def deactivate_user(self, request: Request) -> Response:
        """
        Handle user deactivation request.

        Args:
            request: FastAPI request object

        Returns:
            Response: HTTP response with deactivation result
        """
        try:
            user_id = await self._extract_user_id_from_token(request)

            response_data = {
                "success": True,
                "message": "User deactivation feature not implemented yet",
                "data": {"user_id": user_id}
            }

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                media_type="application/json"
            )

        except InvalidTokenException as e:
            logger.warning(f"Deactivate user failed - invalid token: {e.message}")
            response_data = self.presenter.present_unauthorized_access()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Deactivate user failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def _extract_user_id_from_token(self, request: Request) -> str:
        """
        Extract user ID from JWT token in request header.

        Args:
            request: FastAPI request object

        Returns:
            str: User ID extracted from token

        Raises:
            InvalidTokenException: If token is missing or invalid
        """
        authorization = request.headers.get("Authorization")

        if not authorization or not authorization.startswith("Bearer "):
            raise InvalidTokenException("Missing or invalid authorization header")

        token = authorization.split("Bearer ")[1]
        return self.jwt_service.extract_user_id(token)

    def _serialize_response(self, data: Dict[str, Any]) -> str:
        """
        Serialize response data to JSON string.

        Args:
            data: Response data dictionary

        Returns:
            str: JSON string representation of the response
        """
        import json
        return json.dumps(data, ensure_ascii=False, indent=2)