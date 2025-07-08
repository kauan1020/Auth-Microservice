from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from sqlalchemy.exc import IntegrityError
import uuid

from domain.entities.user import User, UserStatus
from domain.exceptions import UserAlreadyExistsException, UserNotFoundException
from interfaces.repositories.user_repository import UserRepositoryInterface
from infra.databases.models import UserModel


class UserRepository(UserRepositoryInterface):
    """
    PostgreSQL implementation of UserRepositoryInterface.

    This repository handles all database operations related to user management,
    providing CRUD operations and specialized queries for user authentication
    and management workflows.

    It implements the repository pattern to isolate database concerns from
    business logic and provides a clean interface for user data operations.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize the user repository with a database session.

        Args:
            session: AsyncSession for database operations
        """
        self.session = session

    async def create(self, user: User) -> User:
        """
        Create a new user in the database.

        Args:
            user: User entity to be created

        Returns:
            User: Created user with generated ID and timestamps

        Raises:
            UserAlreadyExistsException: If user with same email/username exists
        """
        try:
            user_model = UserModel(
                email=user.email,
                username=user.username,
                password_hash=user.password_hash,
                first_name=user.first_name,
                last_name=user.last_name,
                status=self._map_status_to_enum(user.status),
                created_at=user.created_at,
                updated_at=user.updated_at,
                last_login=user.last_login
            )

            self.session.add(user_model)
            await self.session.flush()
            await self.session.refresh(user_model)

            return self._map_model_to_entity(user_model)

        except IntegrityError as e:
            await self.session.rollback()
            if "email" in str(e.orig):
                raise UserAlreadyExistsException("email", user.email)
            elif "username" in str(e.orig):
                raise UserAlreadyExistsException("username", user.username)
            raise

    async def find_by_id(self, user_id: str) -> Optional[User]:
        """
        Find a user by their unique identifier.

        Args:
            user_id: Unique identifier of the user

        Returns:
            Optional[User]: User entity if found, None otherwise
        """
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return None

        stmt = select(UserModel).where(UserModel.id == user_uuid)
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        return self._map_model_to_entity(user_model) if user_model else None

    async def find_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by their email address.

        Args:
            email: Email address to search for

        Returns:
            Optional[User]: User entity if found, None otherwise
        """
        stmt = select(UserModel).where(UserModel.email == email.lower())
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        return self._map_model_to_entity(user_model) if user_model else None

    async def find_by_username(self, username: str) -> Optional[User]:
        """
        Find a user by their username.

        Args:
            username: Username to search for

        Returns:
            Optional[User]: User entity if found, None otherwise
        """
        stmt = select(UserModel).where(UserModel.username == username.lower())
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        return self._map_model_to_entity(user_model) if user_model else None

    async def update(self, user: User) -> User:
        """
        Update an existing user in the database.

        Args:
            user: User entity with updated information

        Returns:
            User: Updated user entity

        Raises:
            UserNotFoundException: If user doesn't exist
        """
        try:
            user_uuid = uuid.UUID(user.id)
        except (ValueError, TypeError):
            raise UserNotFoundException(user.id)

        stmt = select(UserModel).where(UserModel.id == user_uuid)
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        if not user_model:
            raise UserNotFoundException(user.id)

        user_model.email = user.email
        user_model.username = user.username
        user_model.password_hash = user.password_hash
        user_model.first_name = user.first_name
        user_model.last_name = user.last_name
        user_model.status = self._map_status_to_enum(user.status)
        user_model.updated_at = user.updated_at
        user_model.last_login = user.last_login

        await self.session.flush()
        await self.session.refresh(user_model)

        return self._map_model_to_entity(user_model)

    async def delete(self, user_id: str) -> bool:
        """
        Delete a user from the database.

        Args:
            user_id: Unique identifier of the user to delete

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return False

        stmt = select(UserModel).where(UserModel.id == user_uuid)
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        if user_model:
            await self.session.delete(user_model)
            await self.session.flush()
            return True

        return False

    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user exists with the given email address.

        Args:
            email: Email address to check

        Returns:
            bool: True if user exists, False otherwise
        """
        stmt = select(func.count(UserModel.id)).where(UserModel.email == email.lower())
        result = await self.session.execute(stmt)
        count = result.scalar()
        return count > 0

    async def exists_by_username(self, username: str) -> bool:
        """
        Check if a user exists with the given username.

        Args:
            username: Username to check

        Returns:
            bool: True if user exists, False otherwise
        """
        stmt = select(func.count(UserModel.id)).where(UserModel.username == username.lower())
        result = await self.session.execute(stmt)
        count = result.scalar()
        return count > 0

    async def list_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        List users with pagination support.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List[User]: List of user entities
        """
        stmt = select(UserModel).offset(skip).limit(limit).order_by(UserModel.created_at.desc())
        result = await self.session.execute(stmt)
        user_models = result.scalars().all()

        return [self._map_model_to_entity(model) for model in user_models]

    async def count_users(self) -> int:
        """
        Count the total number of users in the database.

        Returns:
            int: Total number of users
        """
        stmt = select(func.count(UserModel.id))
        result = await self.session.execute(stmt)
        return result.scalar()

    def _map_model_to_entity(self, model: UserModel) -> User:
        """
        Map SQLAlchemy model to domain entity.

        Args:
            model: UserModel instance

        Returns:
            User: Domain entity
        """
        return User(
            id=str(model.id),
            email=model.email,
            username=model.username,
            password_hash=model.password_hash,
            first_name=model.first_name,
            last_name=model.last_name,
            status=self._map_enum_to_status(model.status),
            created_at=model.created_at,
            updated_at=model.updated_at,
            last_login=model.last_login
        )

    def _map_status_to_enum(self, status: UserStatus):
        """
        Map domain UserStatus to SQLAlchemy enum.

        Args:
            status: Domain UserStatus

        Returns:
            UserStatusEnum: SQLAlchemy enum value
        """
        from infra.databases.models import UserStatusEnum
        return UserStatusEnum(status.value)

    def _map_enum_to_status(self, enum_value) -> UserStatus:
        """
        Map SQLAlchemy enum to domain UserStatus.

        Args:
            enum_value: SQLAlchemy enum value

        Returns:
            UserStatus: Domain enum value
        """
        return UserStatus(enum_value.value)