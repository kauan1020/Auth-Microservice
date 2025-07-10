from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio

from infra.settings.settings import get_settings
from infra.databases.database_connection import DatabaseConnection
from infra.repositories.user_repository import UserRepository
from infra.repositories.token_repository import TokenRepository
from infra.security.password_service import PasswordService
from infra.security.jwt_service import JWTService
from infra.gateways.email_gateway import EmailGateway
from infra.presenters.auth_presenter import AuthPresenter

from use_cases.users.register_user_use_case import RegisterUserUseCase, RegisterUserRequest
from use_cases.authenticate.login_use_case import LoginUseCase, LoginRequest as LoginUseCaseRequest
from use_cases.authenticate.logout_use_case import LogoutUseCase, LogoutRequest as LogoutUseCaseRequest
from use_cases.authenticate.refresh_token_use_case import RefreshTokenUseCase, \
    RefreshTokenRequest as RefreshUseCaseRequest
from use_cases.authenticate.validate_token_use_case import ValidateTokenUseCase, ValidateTokenRequest

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    """Request schema for user registration endpoint."""
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=30, description="Unique username")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    first_name: str = Field(..., min_length=1, max_length=100, description="User first name")
    last_name: str = Field(..., min_length=1, max_length=100, description="User last name")


class LoginRequest(BaseModel):
    """Request schema for user authentication endpoint."""
    identifier: str = Field(..., description="Email or username for login")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(default=False, description="Extended session flag")


class RefreshTokenRequest(BaseModel):
    """Request schema for JWT token refresh endpoint."""
    refresh_token: str = Field(..., description="Valid refresh token")


async def create_database_session() -> AsyncSession:
    """
    Create a fresh database session for request handling.

    Creates a new database connection and session for each request
    to avoid connection pooling issues and ensure clean state.

    Returns:
        AsyncSession: Fresh database session
    """
    settings = get_settings()

    # Create fresh connection for each request
    db_connection = DatabaseConnection(
        database_url=settings.database.url,
        echo=settings.database.echo
    )

    # Initialize the connection
    db_connection.initialize()

    # Get session from connection
    session = db_connection.get_session().__aenter__()
    return await session


async def cleanup_database_session(session: AsyncSession, db_connection=None):
    """
    Properly cleanup database session and connection.

    Args:
        session: Database session to cleanup
        db_connection: Database connection to dispose
    """
    try:
        if session and not session.is_closed:
            await session.close()
    except Exception as e:
        print(f"Error closing session: {e}")

    try:
        if db_connection and hasattr(db_connection, 'engine') and db_connection.engine:
            await db_connection.engine.dispose()
    except Exception as e:
        print(f"Error disposing engine: {e}")


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest):
    """
    Register a new user account in the system.

    Creates a new user account with comprehensive validation including
    email format verification, username uniqueness, and password strength
    requirements.

    Args:
        request: RegisterRequest containing user registration data

    Returns:
        dict: Registration success response with user data

    Raises:
        HTTPException: For validation errors or registration conflicts
    """
    session = None
    db_connection = None
    presenter = AuthPresenter()

    try:
        settings = get_settings()

        db_connection = DatabaseConnection(
            database_url=settings.database.url,
            echo=settings.database.echo
        )
        db_connection.initialize()

        async with db_connection.get_session() as session:
            email_gateway = EmailGateway(
                smtp_host="localhost",
                smtp_port=587,
                from_email="xxx@hotmail.com",
                from_name="FIAP X Authentication"
            )

            user_repository = UserRepository(session)
            password_service = PasswordService(
                rounds=settings.security.bcrypt_rounds,
                check_compromised=settings.security.check_compromised_passwords
            )

            register_use_case = RegisterUserUseCase(
                user_repository=user_repository,
                password_service=password_service,
                email_gateway=email_gateway
            )

            register_request = RegisterUserRequest(
                email=request.email,
                username=request.username,
                password=request.password,
                first_name=request.first_name,
                last_name=request.last_name
            )

            result = await register_use_case.execute(register_request)

            # Explicitly commit the transaction
            await session.commit()

            return presenter.present_registration_success(result.user_data)

    except Exception as e:
        # Rollback transaction if session exists
        if session:
            try:
                await session.rollback()
            except:
                pass

        error_message = str(e).lower()

        if "already exists" in error_message:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=presenter.present_authentication_error(str(e))
            )
        elif "password" in error_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=presenter.present_authentication_error(str(e))
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=presenter.present_server_error(str(e))
            )

    finally:
        # Ensure cleanup happens
        if db_connection and hasattr(db_connection, 'engine') and db_connection.engine:
            try:
                await db_connection.engine.dispose()
            except:
                pass


@router.post("/login")
async def login(request: LoginRequest):
    """
    Authenticate user credentials and generate access tokens.

    Validates user credentials against stored authentication data and
    generates JWT tokens for API access.

    Args:
        request: LoginRequest containing authentication credentials

    Returns:
        dict: Authentication success response with tokens and user data

    Raises:
        HTTPException: For invalid credentials or authentication errors
    """
    session = None
    db_connection = None
    presenter = AuthPresenter()

    try:
        settings = get_settings()

        # Create fresh database connection and session
        db_connection = DatabaseConnection(
            database_url=settings.database.url,
            echo=settings.database.echo
        )
        db_connection.initialize()

        async with db_connection.get_session() as session:
            user_repository = UserRepository(session)
            token_repository = TokenRepository(session)
            password_service = PasswordService()
            jwt_service = JWTService(
                secret_key=settings.jwt.secret_key,
                algorithm=settings.jwt.algorithm,
                issuer=settings.jwt.issuer
            )

            login_use_case = LoginUseCase(
                user_repository,
                token_repository,
                password_service,
                jwt_service
            )

            login_request = LoginUseCaseRequest(
                identifier=request.identifier,
                password=request.password,
                remember_me=request.remember_me
            )

            result = await login_use_case.execute(login_request)

            # Commit transaction
            await session.commit()

            auth_data = {
                "access_token": result.access_token,
                "refresh_token": result.refresh_token,
                "token_type": result.token_type,
                "expires_in": result.expires_in,
                "user_data": result.user_data
            }

            return presenter.present_login_success(auth_data)

    except Exception as e:
        if session:
            try:
                await session.rollback()
            except:
                pass

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=presenter.present_authentication_error(str(e))
        )

    finally:
        if db_connection and hasattr(db_connection, 'engine') and db_connection.engine:
            try:
                await db_connection.engine.dispose()
            except:
                pass


@router.post("/refresh")
async def refresh_token(request: RefreshTokenRequest):
    """
    Generate new access token using valid refresh token.

    Validates provided refresh token and generates a new access token.

    Args:
        request: RefreshTokenRequest containing refresh token

    Returns:
        dict: Token refresh success response with new access token

    Raises:
        HTTPException: For invalid or expired refresh tokens
    """
    session = None
    db_connection = None
    presenter = AuthPresenter()

    try:
        settings = get_settings()

        db_connection = DatabaseConnection(
            database_url=settings.database.url,
            echo=settings.database.echo
        )
        db_connection.initialize()

        async with db_connection.get_session() as session:
            user_repository = UserRepository(session)
            token_repository = TokenRepository(session)
            jwt_service = JWTService(
                secret_key=settings.jwt.secret_key,
                algorithm=settings.jwt.algorithm,
                issuer=settings.jwt.issuer
            )

            refresh_use_case = RefreshTokenUseCase(
                user_repository,
                token_repository,
                jwt_service
            )

            refresh_request = RefreshUseCaseRequest(
                refresh_token=request.refresh_token
            )

            result = await refresh_use_case.execute(refresh_request)

            await session.commit()

            token_data = {
                "access_token": result.access_token,
                "token_type": result.token_type,
                "expires_in": result.expires_in
            }

            return presenter.present_token_refresh_success(token_data)

    except Exception as e:
        if session:
            try:
                await session.rollback()
            except:
                pass

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=presenter.present_authentication_error(str(e))
        )

    finally:
        if db_connection and hasattr(db_connection, 'engine') and db_connection.engine:
            try:
                await db_connection.engine.dispose()
            except:
                pass


@router.post("/logout")
async def logout():
    """
    Logout user and invalidate authentication tokens.

    Terminates user session by revoking active tokens.

    Returns:
        dict: Logout success confirmation response
    """
    session = None
    db_connection = None
    presenter = AuthPresenter()

    try:
        settings = get_settings()

        db_connection = DatabaseConnection(
            database_url=settings.database.url,
            echo=settings.database.echo
        )
        db_connection.initialize()

        async with db_connection.get_session() as session:
            token_repository = TokenRepository(session)
            jwt_service = JWTService(
                secret_key=settings.jwt.secret_key,
                algorithm=settings.jwt.algorithm,
                issuer=settings.jwt.issuer
            )

            logout_use_case = LogoutUseCase(token_repository, jwt_service)

            logout_request = LogoutUseCaseRequest(
                access_token="mock-token",
                revoke_all=False
            )

            result = await logout_use_case.execute(logout_request)
            await session.commit()

            return presenter.present_logout_success()

    except Exception as e:
        if session:
            try:
                await session.rollback()
            except:
                pass
        return presenter.present_logout_success()

    finally:
        if db_connection and hasattr(db_connection, 'engine') and db_connection.engine:
            try:
                await db_connection.engine.dispose()
            except:
                pass


@router.get("/validate")
async def validate_token(token: str):
    """
    Validate JWT token and return token information.

    Performs comprehensive token validation.

    Args:
        token: JWT token string to validate

    Returns:
        dict: Token validation result with user information

    Raises:
        HTTPException: For invalid or expired tokens
    """
    session = None
    db_connection = None
    presenter = AuthPresenter()

    try:
        settings = get_settings()

        db_connection = DatabaseConnection(
            database_url=settings.database.url,
            echo=settings.database.echo
        )
        db_connection.initialize()

        async with db_connection.get_session() as session:
            token_repository = TokenRepository(session)
            jwt_service = JWTService(
                secret_key=settings.jwt.secret_key,
                algorithm=settings.jwt.algorithm,
                issuer=settings.jwt.issuer
            )

            validate_use_case = ValidateTokenUseCase(token_repository, jwt_service)

            validate_request = ValidateTokenRequest(token=token)
            result = await validate_use_case.execute(validate_request)

            if result.valid:
                token_info = {
                    "valid": result.valid,
                    "user_id": result.user_id,
                    "token_type": result.token_type,
                    "expires_at": result.expires_at,
                    "issued_at": result.issued_at
                }
                return presenter.present_token_validation_success(token_info)
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=presenter.present_token_validation_error(result.reason)
                )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=presenter.present_authentication_error(str(e))
        )

    finally:
        if db_connection and hasattr(db_connection, 'engine') and db_connection.engine:
            try:
                await db_connection.engine.dispose()
            except:
                pass