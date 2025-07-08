from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from typing import Any, Dict


class RegisterUserSchema(BaseModel):
    """
    Schema for user registration request validation.

    Validates and serializes user registration data ensuring
    all required fields are present and properly formatted.
    """

    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=30, description="Unique username")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    first_name: str = Field(..., min_length=1, max_length=100, description="User first name")
    last_name: str = Field(..., min_length=1, max_length=100, description="User last name")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "username": "johndoe",
                "password": "SecurePass123!",
                "first_name": "John",
                "last_name": "Doe"
            }
        }


class LoginUserSchema(BaseModel):
    """
    Schema for user login request validation.

    Validates login credentials ensuring proper format
    and required fields are present.
    """

    identifier: str = Field(..., description="Email or username for login")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(default=False, description="Extended session flag")

    class Config:
        json_schema_extra = {
            "example": {
                "identifier": "user@example.com",
                "password": "SecurePass123!",
                "remember_me": False
            }
        }


class RefreshTokenSchema(BaseModel):
    """
    Schema for token refresh request validation.

    Validates refresh token request ensuring proper
    token format and required fields.
    """

    refresh_token: str = Field(..., description="Valid refresh token")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class TokenValidationSchema(BaseModel):
    """
    Schema for token validation request.

    Validates token validation request ensuring
    proper token format.
    """

    token: str = Field(..., description="JWT token to validate")

    class Config:
        json_schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


# interfaces/schemas/user_schemas.py
class UpdateUserProfileSchema(BaseModel):
    """
    Schema for user profile update request validation.

    Validates user profile update data allowing
    optional field updates.
    """

    first_name: Optional[str] = Field(None, min_length=1, max_length=100, description="User first name")
    last_name: Optional[str] = Field(None, min_length=1, max_length=100, description="User last name")
    username: Optional[str] = Field(None, min_length=3, max_length=30, description="Unique username")

    class Config:
        json_schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "username": "johndoe_updated"
            }
        }


class ChangePasswordSchema(BaseModel):
    """
    Schema for password change request validation.

    Validates password change request ensuring
    current and new passwords are provided.
    """

    current_password: str = Field(..., description="Current user password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")
    confirm_password: str = Field(..., description="New password confirmation")

    class Config:
        json_schema_extra = {
            "example": {
                "current_password": "OldPassword123!",
                "new_password": "NewSecurePass456!",
                "confirm_password": "NewSecurePass456!"
            }
        }


class UserProfileResponseSchema(BaseModel):
    """
    Schema for user profile response serialization.

    Defines the structure of user profile data
    returned by the API.
    """

    id: str = Field(..., description="User unique identifier")
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="User username")
    first_name: str = Field(..., description="User first name")
    last_name: str = Field(..., description="User last name")
    full_name: str = Field(..., description="User full name")
    status: str = Field(..., description="User account status")
    created_at: str = Field(..., description="Account creation timestamp")
    last_login: Optional[str] = Field(None, description="Last login timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "user@example.com",
                "username": "johndoe",
                "first_name": "John",
                "last_name": "Doe",
                "full_name": "John Doe",
                "status": "active",
                "created_at": "2024-01-15T10:30:00Z",
                "last_login": "2024-01-20T14:45:00Z"
            }
        }


# interfaces/schemas/response_schemas.py
class SuccessResponseSchema(BaseModel):
    """
    Schema for successful API response.

    Standardizes successful response format across
    all API endpoints.
    """

    success: bool = Field(default=True, description="Request success status")
    message: str = Field(..., description="Success message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Operation completed successfully",
                "data": {}
            }
        }


class ErrorResponseSchema(BaseModel):
    """
    Schema for error API response.

    Standardizes error response format across
    all API endpoints.
    """

    success: bool = Field(default=False, description="Request success status")
    message: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Specific error code")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")

    class Config:
        json_schema_extra = {
            "example": {
                "success": False,
                "message": "Validation error occurred",
                "error_code": "VALIDATION_ERROR",
                "details": {
                    "field_errors": {
                        "email": ["Invalid email format"]
                    }
                }
            }
        }


class AuthenticationResponseSchema(BaseModel):
    """
    Schema for authentication response.

    Defines the structure of authentication success
    response including tokens and user data.
    """

    success: bool = Field(default=True, description="Authentication success status")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")
    user: UserProfileResponseSchema = Field(..., description="User profile data")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 900,
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "email": "user@example.com",
                    "username": "johndoe",
                    "first_name": "John",
                    "last_name": "Doe",
                    "full_name": "John Doe",
                    "status": "active",
                    "created_at": "2024-01-15T10:30:00Z",
                    "last_login": "2024-01-20T14:45:00Z"
                }
            }
        }


class TokenRefreshResponseSchema(BaseModel):
    """
    Schema for token refresh response.

    Defines the structure of token refresh success
    response with new access token.
    """

    success: bool = Field(default=True, description="Token refresh success status")
    access_token: str = Field(..., description="New JWT access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 900
            }
        }