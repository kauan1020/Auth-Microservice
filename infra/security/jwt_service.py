import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from domain.entities.auth_token import AuthToken
from domain.exceptions import InvalidTokenException, TokenExpiredException
from interfaces.services.jwt_service import JWTServiceInterface


class JWTService(JWTServiceInterface):
    """
    Implementation of JWT token management using PyJWT library.

    This service handles JWT token creation, validation, and claim management
    with secure encryption algorithms and proper error handling.

    It provides comprehensive token lifecycle management including generation,
    validation, expiration checking, and claim extraction capabilities.
    """

    def __init__(self, secret_key: str, algorithm: str = "HS256", issuer: str = "fiap-x-auth"):
        """
        Initialize JWT service with configuration parameters.

        Args:
            secret_key: Secret key for token signing and validation
            algorithm: JWT signing algorithm (HS256, RS256, etc.)
            issuer: Token issuer identifier
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = issuer

    def generate_token(self, token: AuthToken, claims: Dict[str, Any]) -> str:
        """
        Generate a JWT token string from an AuthToken entity and claims.

        Args:
            token: AuthToken entity containing token metadata
            claims: Dictionary of claims to include in the JWT payload

        Returns:
            str: Generated JWT token string
        """
        payload = {
            "iss": self.issuer,
            "sub": token.user_id,
            "type": token.token_type.value,
            "iat": int(token.created_at.timestamp()) if token.created_at else int(datetime.utcnow().timestamp()),
            "exp": int(token.expires_at.timestamp()),
            "jti": token.token if hasattr(token, 'jti') else None
        }

        payload.update(claims)

        try:
            return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        except Exception as e:
            raise InvalidTokenException(f"Token generation failed: {str(e)}")

    def decode_token(self, token_string: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token string.

        Args:
            token_string: JWT token string to decode

        Returns:
            Dict[str, Any]: Dictionary containing token claims

        Raises:
            InvalidTokenException: If token is malformed or invalid
            TokenExpiredException: If token has expired
        """
        try:
            payload = jwt.decode(
                token_string,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True
                }
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise TokenExpiredException()
        except jwt.InvalidTokenError as e:
            raise InvalidTokenException(f"Invalid token: {str(e)}")
        except Exception as e:
            raise InvalidTokenException(f"Token decode error: {str(e)}")

    def extract_user_id(self, token_string: str) -> str:
        """
        Extract user ID from a JWT token.

        Args:
            token_string: JWT token string

        Returns:
            str: User ID extracted from token claims

        Raises:
            InvalidTokenException: If token is invalid or missing user ID
        """
        try:
            payload = self.decode_token(token_string)
            user_id = payload.get("sub")

            if not user_id:
                raise InvalidTokenException("Token missing user ID claim")

            return user_id

        except (TokenExpiredException, InvalidTokenException):
            raise
        except Exception as e:
            raise InvalidTokenException(f"Failed to extract user ID: {str(e)}")

    def extract_token_type(self, token_string: str) -> str:
        """
        Extract token type from a JWT token.

        Args:
            token_string: JWT token string

        Returns:
            str: Token type (access or refresh)

        Raises:
            InvalidTokenException: If token is invalid or missing token type
        """
        try:
            payload = self.decode_token(token_string)
            token_type = payload.get("type")

            if not token_type:
                raise InvalidTokenException("Token missing type claim")

            return token_type

        except (TokenExpiredException, InvalidTokenException):
            raise
        except Exception as e:
            raise InvalidTokenException(f"Failed to extract token type: {str(e)}")

    def is_token_expired(self, token_string: str) -> bool:
        """
        Check if a JWT token has expired without raising exceptions.

        Args:
            token_string: JWT token string to check

        Returns:
            bool: True if token is expired, False otherwise
        """
        try:
            self.decode_token(token_string)
            return False
        except TokenExpiredException:
            return True
        except InvalidTokenException:
            return True

    def get_token_expiration(self, token_string: str) -> Optional[int]:
        """
        Get the expiration timestamp from a JWT token.

        Args:
            token_string: JWT token string

        Returns:
            Optional[int]: Unix timestamp of token expiration, None if not found
        """
        try:
            payload = jwt.decode(
                token_string,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}
            )
            return payload.get("exp")

        except Exception:
            return None

    def refresh_token_claims(self, refresh_token: str) -> Dict[str, Any]:
        """
        Extract claims from a refresh token for generating new access token.

        Args:
            refresh_token: Refresh token string

        Returns:
            Dict[str, Any]: Dictionary containing claims for new access token

        Raises:
            InvalidTokenException: If refresh token is invalid
            TokenExpiredException: If refresh token has expired
        """
        payload = self.decode_token(refresh_token)

        if payload.get("type") != "refresh":
            raise InvalidTokenException("Token is not a refresh token")

        claims = {
            "username": payload.get("username"),
            "email": payload.get("email")
        }

        claims = {k: v for k, v in claims.items() if v is not None}

        return claims

    def create_token_claims(self, user_id: str, token_type: str,
                            additional_claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create standardized claims dictionary for JWT token generation.

        Args:
            user_id: User identifier
            token_type: Type of token (access or refresh)
            additional_claims: Optional additional claims to include

        Returns:
            Dict[str, Any]: Dictionary containing standardized JWT claims
        """
        claims = {
            "user_id": user_id,
            "token_type": token_type
        }

        if additional_claims:
            claims.update(additional_claims)

        return claims