from fastapi import Request, Response, status
from typing import Dict, Any
import logging

from interfaces.controllers.auth_controller import AuthControllerInterface
from interfaces.presenters.auth_presenter import AuthPresenterInterface
from use_cases.users.register_user_use_case import RegisterUserUseCase, RegisterUserRequest
from use_cases.authenticate.login_use_case import LoginUseCase, LoginRequest
from use_cases.authenticate.logout_use_case import LogoutUseCase, LogoutRequest
from use_cases.authenticate.validate_token_use_case import ValidateTokenUseCase, ValidateTokenRequest
from use_cases.authenticate.refresh_token_use_case import RefreshTokenUseCase, RefreshTokenRequest
from domain.exceptions import (
    AuthenticationException,
    UserAlreadyExistsException,
    InvalidCredentialsException,
    WeakPasswordException,
    TokenExpiredException,
    InvalidTokenException
)

logger = logging.getLogger(__name__)


class AuthController(AuthControllerInterface):
    """
    Implementation of authentication controller for HTTP request handling.

    This controller handles all authentication-related HTTP requests,
    coordinating between use cases and presenters to provide proper
    API responses while maintaining clean separation of concerns.

    It manages request validation, use case execution, error handling,
    and response formatting for authentication operations.
    """

    def __init__(self,
                 register_use_case: RegisterUserUseCase,
                 login_use_case: LoginUseCase,
                 logout_use_case: LogoutUseCase,
                 refresh_token_use_case: RefreshTokenUseCase,
                 validate_token_use_case: ValidateTokenUseCase,
                 presenter: AuthPresenterInterface):
        """
        Initialize the authentication controller.

        Args:
            register_use_case: Use case for user registration
            login_use_case: Use case for user authentication
            logout_use_case: Use case for user logout
            refresh_token_use_case: Use case for token refresh
            validate_token_use_case: Use case for token validation
            presenter: Presenter for formatting responses
        """
        self.register_use_case = register_use_case
        self.login_use_case = login_use_case
        self.logout_use_case = logout_use_case
        self.refresh_token_use_case = refresh_token_use_case
        self.validate_token_use_case = validate_token_use_case
        self.presenter = presenter

    async def register(self, request: Request) -> Response:
        """
        Handle user registration HTTP request.

        Args:
            request: FastAPI request object containing registration data

        Returns:
            Response: HTTP response with registration result
        """
        try:
            request_data = await request.json()

            register_request = RegisterUserRequest(
                email=request_data.get("email"),
                username=request_data.get("username"),
                password=request_data.get("password"),
                first_name=request_data.get("first_name"),
                last_name=request_data.get("last_name")
            )

            result = await self.register_use_case.execute(register_request)
            response_data = self.presenter.present_registration_success(result.user_data)

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_201_CREATED,
                media_type="application/json"
            )

        except UserAlreadyExistsException as e:
            logger.warning(f"Registration failed - user exists: {e.message}")
            response_data = self.presenter.present_authentication_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_409_CONFLICT,
                media_type="application/json"
            )

        except WeakPasswordException as e:
            logger.warning(f"Registration failed - weak password: {e.message}")
            response_data = self.presenter.present_authentication_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="application/json"
            )

        except ValueError as e:
            logger.warning(f"Registration failed - validation error: {str(e)}")
            response_data = self.presenter.present_validation_error({"general": [str(e)]})
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Registration failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def login(self, request: Request) -> Response:
        """
        Handle user login HTTP request.

        Args:
            request: FastAPI request object containing login credentials

        Returns:
            Response: HTTP response with authentication result
        """
        try:
            request_data = await request.json()

            auth_request = LoginRequest(
                identifier=request_data.get("identifier"),
                password=request_data.get("password"),
                remember_me=request_data.get("remember_me", False)
            )

            result = await self.login_use_case.execute(auth_request)
            response_data = self.presenter.present_login_success({
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
                "token_type": result.token_type,
                "expires_in": result.expires_in,
                "user_data": result.user_data
            })

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_200_OK,
                media_type="application/json"
            )

        except InvalidCredentialsException as e:
            logger.warning(f"Login failed - invalid credentials: {e.message}")
            response_data = self.presenter.present_authentication_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except AuthenticationException as e:
            logger.warning(f"Login failed - authentication error: {e.message}")
            response_data = self.presenter.present_authentication_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Login failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def logout(self, request: Request) -> Response:
        """
        Handle user logout HTTP request.

        Args:
            request: FastAPI request object containing logout information

        Returns:
            Response: HTTP response with logout result
        """
        try:
            authorization = request.headers.get("Authorization")
            if not authorization or not authorization.startswith("Bearer "):
                response_data = self.presenter.present_authentication_error("Missing or invalid authorization header")
                return Response(
                    content=self._serialize_response(response_data),
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    media_type="application/json"
                )

            access_token = authorization.split("Bearer ")[1]
            request_data = await request.json() if request.method == "POST" else {}

            logout_request = LogoutRequest(
                access_token=access_token,
                revoke_all=request_data.get("revoke_all", False)
            )

            result = await self.logout_use_case.execute(logout_request)
            response_data = self.presenter.present_logout_success()

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_200_OK,
                media_type="application/json"
            )

        except InvalidTokenException as e:
            logger.warning(f"Logout failed - invalid token: {e.message}")
            response_data = self.presenter.present_authentication_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Logout failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def refresh_token(self, request: Request) -> Response:
        """
        Handle token refresh HTTP request.

        Args:
            request: FastAPI request object containing refresh token

        Returns:
            Response: HTTP response with new access token
        """
        try:
            request_data = await request.json()

            refresh_request = RefreshTokenRequest(
                refresh_token=request_data.get("refresh_token")
            )

            result = await self.refresh_token_use_case.execute(refresh_request)
            response_data = self.presenter.present_token_refresh_success({
                "access_token": result.access_token,
                "token_type": result.token_type,
                "expires_in": result.expires_in
            })

            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_200_OK,
                media_type="application/json"
            )

        except (TokenExpiredException, InvalidTokenException) as e:
            logger.warning(f"Token refresh failed: {e.message}")
            response_data = self.presenter.present_authentication_error(e.message)
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )

        except Exception as e:
            logger.error(f"Token refresh failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

    async def validate_token(self, request: Request) -> Response:
        """
        Handle token validation HTTP request.

        Args:
            request: FastAPI request object containing token to validate

        Returns:
            Response: HTTP response with token validation result
        """
        try:
            authorization = request.headers.get("Authorization")
            if authorization and authorization.startswith("Bearer "):
                token = authorization.split("Bearer ")[1]
            else:
                request_data = await request.json()
                token = request_data.get("token")

            if not token:
                response_data = self.presenter.present_authentication_error("Token is required")
                return Response(
                    content=self._serialize_response(response_data),
                    status_code=status.HTTP_400_BAD_REQUEST,
                    media_type="application/json"
                )

            result = await self.validate_token_use_case.execute(ValidateTokenRequest(token=token))

            if result.valid:
                response_data = self.presenter.present_token_validation_success({
                    "valid": result.valid,
                    "user_id": result.user_id,
                    "token_type": result.token_type,
                    "expires_at": result.expires_at,
                    "issued_at": result.issued_at
                })
                return Response(
                    content=self._serialize_response(response_data),
                    status_code=status.HTTP_200_OK,
                    media_type="application/json"
                )
            else:
                response_data = self.presenter.present_token_validation_error(result.reason)
                return Response(
                    content=self._serialize_response(response_data),
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    media_type="application/json"
                )

        except Exception as e:
            logger.error(f"Token validation failed - server error: {str(e)}")
            response_data = self.presenter.present_server_error()
            return Response(
                content=self._serialize_response(response_data),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                media_type="application/json"
            )

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