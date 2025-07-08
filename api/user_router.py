from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from infra.settings.settings import get_settings
from infra.databases.database_connection import DatabaseConnection
from infra.repositories.user_repository import UserRepository
from infra.security.password_service import PasswordService
from infra.security.jwt_service import JWTService
from infra.presenters.user_presenter import UserPresenter

from use_cases.users.get_user_use_case import GetUserUseCase, GetUserRequest
from use_cases.users.update_user_use_case import UpdateUserUseCase, UpdateUserRequest
from use_cases.users.change_password_use_case import ChangePasswordUseCase, \
    ChangePasswordRequest as ChangePasswordUseCaseRequest

router = APIRouter(prefix="/users", tags=["User Management"])


class UpdateProfileRequest(BaseModel):
    """
    Request schema for user profile update operations.

    Validates optional profile fields allowing partial updates
    with proper constraints and type validation for data integrity.
    """
    first_name: Optional[str] = Field(None, min_length=1, max_length=100, description="User first name")
    last_name: Optional[str] = Field(None, min_length=1, max_length=100, description="User last name")
    username: Optional[str] = Field(None, min_length=3, max_length=30, description="Unique username")


class ChangePasswordRequest(BaseModel):
    """
    Request schema for user password change operations.

    Validates password change requirements including current password
    verification and new password strength confirmation.
    """
    current_password: str = Field(..., description="Current user password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")
    confirm_password: str = Field(..., description="New password confirmation")


async def get_database_session() -> AsyncSession:
    """
    Create and return database session for request handling.

    Initializes database connection with proper configuration and
    returns async session for repository operations.

    Returns:
        AsyncSession: Configured database session
    """
    settings = get_settings()
    db_connection = DatabaseConnection(
        database_url=settings.database.url,
        echo=settings.database.echo
    )
    db_connection.initialize()

    async with db_connection.get_session() as session:
        return session


@router.get("/profile")
async def get_profile(user_id: str = "mock-user-id"):
    """
    Retrieve current user profile information and account details.

    Returns comprehensive user profile data including personal information,
    account status, and timestamp details using complete Clean Architecture
    flow with repositories and use cases.

    Args:
        user_id: User identifier for profile retrieval

    Returns:
        dict: User profile data with account information

    Raises:
        HTTPException: For authentication or authorization errors
    """
    try:
        session = await get_database_session()

        user_repository = UserRepository(session)
        presenter = UserPresenter()

        get_user_use_case = GetUserUseCase(user_repository)

        get_user_request = GetUserRequest(user_id=user_id)
        result = await get_user_use_case.execute(get_user_request)

        return presenter.present_user_profile(result.user_data)

    except Exception as e:
        presenter = UserPresenter()
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=presenter.present_user_not_found()
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=presenter.present_server_error(str(e))
            )


@router.put("/profile")
async def update_profile(request: UpdateProfileRequest, user_id: str = "mock-user-id"):
    """
    Update user profile information with provided data.

    Processes partial profile updates allowing modification of personal
    information while maintaining data integrity and uniqueness constraints
    using complete Clean Architecture flow.

    Args:
        request: UpdateProfileRequest containing fields to update
        user_id: User identifier for profile update

    Returns:
        dict: Updated profile confirmation with modified data

    Raises:
        HTTPException: For validation errors or update conflicts
    """
    try:
        session = await get_database_session()

        user_repository = UserRepository(session)
        presenter = UserPresenter()

        update_user_use_case = UpdateUserUseCase(user_repository)

        update_request = UpdateUserRequest(
            user_id=user_id,
            first_name=request.first_name,
            last_name=request.last_name,
            username=request.username
        )

        result = await update_user_use_case.execute(update_request)
        return presenter.present_profile_update_success(result.user_data)

    except Exception as e:
        presenter = UserPresenter()
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=presenter.present_user_not_found()
            )
        elif "already exists" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=presenter.present_user_already_exists("username", "")
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=presenter.present_server_error(str(e))
            )


@router.post("/change-password")
async def change_password(request: ChangePasswordRequest, user_id: str = "mock-user-id"):
    """
    Change user account password with security validation.

    Validates current password authentication and applies new password
    with strength requirements and confirmation matching verification
    using complete Clean Architecture flow with proper security checks.

    Args:
        request: ChangePasswordRequest containing password change data
        user_id: User identifier for password change

    Returns:
        dict: Password change success confirmation

    Raises:
        HTTPException: For authentication or validation errors
    """
    try:
        settings = get_settings()
        session = await get_database_session()

        user_repository = UserRepository(session)
        password_service = PasswordService(
            rounds=settings.security.bcrypt_rounds,
            check_compromised=settings.security.check_compromised_passwords
        )
        presenter = UserPresenter()

        if request.new_password != request.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=presenter.present_validation_error({
                    "confirm_password": ["Password confirmation does not match"]
                })
            )

        change_password_use_case = ChangePasswordUseCase(user_repository, password_service)

        change_password_request = ChangePasswordUseCaseRequest(
            user_id=user_id,
            current_password=request.current_password,
            new_password=request.new_password
        )

        result = await change_password_use_case.execute(change_password_request)
        return presenter.present_password_change_success()

    except HTTPException:
        raise
    except Exception as e:
        presenter = UserPresenter()
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=presenter.present_user_not_found()
            )
        elif "invalid credentials" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=presenter.present_validation_error({
                    "current_password": ["Current password is incorrect"]
                })
            )
        elif "password" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=presenter.present_password_validation_error(str(e))
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=presenter.present_server_error(str(e))
            )