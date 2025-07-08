class AuthenticationException(Exception):
    """
    Base exception for authentication-related errors.

    This is the parent class for all authentication domain exceptions,
    providing a common interface for handling authentication failures.
    """

    def __init__(self, message: str = "Authentication failed"):
        self.message = message
        super().__init__(self.message)


class UserNotFoundException(AuthenticationException):
    """
    Exception raised when a requested user cannot be found.

    This exception is thrown when attempting to retrieve or operate
    on a user that doesn't exist in the system.
    """

    def __init__(self, identifier: str):
        message = f"User not found: {identifier}"
        super().__init__(message)


class UserAlreadyExistsException(AuthenticationException):
    """
    Exception raised when attempting to create a user that already exists.

    This exception is thrown during user registration when the email
    or username is already taken by another user.
    """

    def __init__(self, field: str, value: str):
        message = f"User already exists with {field}: {value}"
        super().__init__(message)


class InvalidCredentialsException(AuthenticationException):
    """
    Exception raised when provided credentials are invalid.

    This exception is thrown during login attempts when the provided
    email/username and password combination is incorrect.
    """

    def __init__(self):
        message = "Invalid email/username or password"
        super().__init__(message)


class UserBlockedException(AuthenticationException):
    """
    Exception raised when attempting to authenticate a blocked user.

    This exception is thrown when a user with blocked status
    attempts to login or perform authenticated actions.
    """

    def __init__(self, user_id: str):
        message = f"User account is blocked: {user_id}"
        super().__init__(message)


class UserInactiveException(AuthenticationException):
    """
    Exception raised when attempting to authenticate an inactive user.

    This exception is thrown when a user with inactive status
    attempts to login or perform authenticated actions.
    """

    def __init__(self, user_id: str):
        message = f"User account is inactive: {user_id}"
        super().__init__(message)


class TokenExpiredException(AuthenticationException):
    """
    Exception raised when attempting to use an expired token.

    This exception is thrown when a JWT token has passed its
    expiration time and can no longer be used for authentication.
    """

    def __init__(self):
        message = "Token has expired"
        super().__init__(message)


class TokenRevokedException(AuthenticationException):
    """
    Exception raised when attempting to use a revoked token.

    This exception is thrown when a JWT token has been explicitly
    revoked and can no longer be used for authentication.
    """

    def __init__(self):
        message = "Token has been revoked"
        super().__init__(message)


class InvalidTokenException(AuthenticationException):
    """
    Exception raised when a token is malformed or invalid.

    This exception is thrown when a JWT token cannot be decoded
    or contains invalid/missing claims.
    """

    def __init__(self, reason: str = "Token is invalid"):
        message = f"Invalid token: {reason}"
        super().__init__(message)


class WeakPasswordException(AuthenticationException):
    """
    Exception raised when a password doesn't meet security requirements.

    This exception is thrown during user registration or password
    change when the provided password is too weak.
    """

    def __init__(self, requirements: str):
        message = f"Password doesn't meet requirements: {requirements}"
        super().__init__(message)