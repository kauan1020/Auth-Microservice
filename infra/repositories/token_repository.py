from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, and_
from datetime import datetime
import uuid

from domain.entities.auth_token import AuthToken, TokenType
from interfaces.repositories.token_repository import TokenRepositoryInterface
from infra.databases.models import TokenModel, TokenTypeEnum


class TokenRepository(TokenRepositoryInterface):
    """
    PostgreSQL implementation of TokenRepositoryInterface.

    This repository handles all database operations related to authentication
    token management, including token storage, validation, revocation, and cleanup.

    It provides efficient token lookup and management operations optimized
    for high-performance authentication workflows.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize the token repository with a database session.

        Args:
            session: AsyncSession for database operations
        """
        self.session = session

    async def create(self, token: AuthToken) -> AuthToken:
        """
        Store a new token in the database.

        Args:
            token: AuthToken entity to be stored

        Returns:
            AuthToken: Stored token with any generated fields
        """
        token_model = TokenModel(
            token=token.token,
            token_type=self._map_type_to_enum(token.token_type),
            user_id=uuid.UUID(token.user_id),
            expires_at=token.expires_at,
            created_at=token.created_at,
            is_revoked=token.is_revoked
        )

        self.session.add(token_model)
        await self.session.flush()
        await self.session.refresh(token_model)

        return self._map_model_to_entity(token_model)

    async def find_by_token(self, token_string: str) -> Optional[AuthToken]:
        """
        Find a token by its string value.

        Args:
            token_string: JWT token string to search for

        Returns:
            Optional[AuthToken]: Token entity if found, None otherwise
        """
        stmt = select(TokenModel).where(TokenModel.token == token_string)
        result = await self.session.execute(stmt)
        token_model = result.scalar_one_or_none()

        return self._map_model_to_entity(token_model) if token_model else None

    async def find_by_user_id(self, user_id: str, token_type: TokenType) -> List[AuthToken]:
        """
        Find all tokens for a specific user and token type.

        Args:
            user_id: User identifier
            token_type: Type of tokens to retrieve

        Returns:
            List[AuthToken]: List of tokens matching the criteria
        """
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return []

        stmt = select(TokenModel).where(
            and_(
                TokenModel.user_id == user_uuid,
                TokenModel.token_type == self._map_type_to_enum(token_type)
            )
        ).order_by(TokenModel.created_at.desc())

        result = await self.session.execute(stmt)
        token_models = result.scalars().all()

        return [self._map_model_to_entity(model) for model in token_models]

    async def find_active_tokens_by_user(self, user_id: str) -> List[AuthToken]:
        """
        Find all active (non-expired, non-revoked) tokens for a user.

        Args:
            user_id: User identifier

        Returns:
            List[AuthToken]: List of active tokens for the user
        """
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return []

        now = datetime.utcnow()
        stmt = select(TokenModel).where(
            and_(
                TokenModel.user_id == user_uuid,
                TokenModel.is_revoked == False,
                TokenModel.expires_at > now
            )
        ).order_by(TokenModel.created_at.desc())

        result = await self.session.execute(stmt)
        token_models = result.scalars().all()

        return [self._map_model_to_entity(model) for model in token_models]

    async def revoke_token(self, token_string: str) -> bool:
        """
        Revoke a specific token by marking it as revoked.

        Args:
            token_string: JWT token string to revoke

        Returns:
            bool: True if token was successfully revoked, False otherwise
        """
        stmt = update(TokenModel).where(
            TokenModel.token == token_string
        ).values(is_revoked=True)

        result = await self.session.execute(stmt)
        await self.session.flush()

        return result.rowcount > 0

    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a specific user.

        Args:
            user_id: User identifier

        Returns:
            int: Number of tokens revoked
        """
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return 0

        stmt = update(TokenModel).where(
            and_(
                TokenModel.user_id == user_uuid,
                TokenModel.is_revoked == False
            )
        ).values(is_revoked=True)

        result = await self.session.execute(stmt)
        await self.session.flush()

        return result.rowcount

    async def revoke_user_tokens_by_type(self, user_id: str, token_type: TokenType) -> int:
        """
        Revoke all tokens of a specific type for a user.

        Args:
            user_id: User identifier
            token_type: Type of tokens to revoke

        Returns:
            int: Number of tokens revoked
        """
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return 0

        stmt = update(TokenModel).where(
            and_(
                TokenModel.user_id == user_uuid,
                TokenModel.token_type == self._map_type_to_enum(token_type),
                TokenModel.is_revoked == False
            )
        ).values(is_revoked=True)

        result = await self.session.execute(stmt)
        await self.session.flush()

        return result.rowcount

    async def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from the database.

        This method removes tokens that are past their expiration time
        to maintain database performance and storage efficiency.

        Returns:
            int: Number of expired tokens removed
        """
        now = datetime.utcnow()
        stmt = delete(TokenModel).where(TokenModel.expires_at < now)

        result = await self.session.execute(stmt)
        await self.session.flush()

        return result.rowcount

    async def is_token_revoked(self, token_string: str) -> bool:
        """
        Check if a token has been revoked.

        Args:
            token_string: JWT token string to check

        Returns:
            bool: True if token is revoked, False otherwise
        """
        stmt = select(TokenModel.is_revoked).where(TokenModel.token == token_string)
        result = await self.session.execute(stmt)
        is_revoked = result.scalar_one_or_none()

        return is_revoked is True

    async def update_token(self, token: AuthToken) -> AuthToken:
        """
        Update an existing token in the database.

        Args:
            token: AuthToken entity with updated information

        Returns:
            AuthToken: Updated token entity
        """
        stmt = update(TokenModel).where(
            TokenModel.token == token.token
        ).values(
            expires_at=token.expires_at,
            is_revoked=token.is_revoked
        ).returning(TokenModel)

        result = await self.session.execute(stmt)
        await self.session.flush()
        token_model = result.scalar_one()

        return self._map_model_to_entity(token_model)

    def _map_model_to_entity(self, model: TokenModel) -> AuthToken:
        """
        Map SQLAlchemy model to domain entity.

        Args:
            model: TokenModel instance

        Returns:
            AuthToken: Domain entity
        """
        return AuthToken(
            token=model.token,
            token_type=self._map_enum_to_type(model.token_type),
            user_id=str(model.user_id),
            expires_at=model.expires_at,
            created_at=model.created_at,
            is_revoked=model.is_revoked
        )

    def _map_type_to_enum(self, token_type: TokenType) -> TokenTypeEnum:
        """
        Map domain TokenType to SQLAlchemy enum.

        Args:
            token_type: Domain TokenType

        Returns:
            TokenTypeEnum: SQLAlchemy enum value
        """
        return TokenTypeEnum(token_type.value)

    def _map_enum_to_type(self, enum_value: TokenTypeEnum) -> TokenType:
        """
        Map SQLAlchemy enum to domain TokenType.

        Args:
            enum_value: SQLAlchemy enum value

        Returns:
            TokenType: Domain enum value
        """
        return TokenType(enum_value.value)