from abc import ABC, abstractmethod
from typing import Optional, List
from domain.entities.user import User


class UserRepositoryInterface(ABC):
    """
    Repository interface for User entity operations.

    This interface defines the contract for user data persistence operations,
    following the Repository pattern to abstract data access concerns from
    the business logic layer.

    The implementation of this interface should handle all database operations
    related to user management, including CRUD operations and specialized queries.
    """

    @abstractmethod
    async def create(self, user: User) -> User:
        """
        Create a new user in the repository.

        Args:
            user: User entity to be created

        Returns:
            User: Created user with generated ID and timestamps

        Raises:
            UserAlreadyExistsException: If user with same email/username exists
        """
        pass

    @abstractmethod
    async def find_by_id(self, user_id: str) -> Optional[User]:
        """
        Find a user by their unique identifier.

        Args:
            user_id: Unique identifier of the user

        Returns:
            Optional[User]: User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by their email address.

        Args:
            email: Email address to search for

        Returns:
            Optional[User]: User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_username(self, username: str) -> Optional[User]:
        """
        Find a user by their username.

        Args:
            username: Username to search for

        Returns:
            Optional[User]: User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def update(self, user: User) -> User:
        """
        Update an existing user in the repository.

        Args:
            user: User entity with updated information

        Returns:
            User: Updated user entity

        Raises:
            UserNotFoundException: If user doesn't exist
        """
        pass

    @abstractmethod
    async def delete(self, user_id: str) -> bool:
        """
        Delete a user from the repository.

        Args:
            user_id: Unique identifier of the user to delete

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user exists with the given email address.

        Args:
            email: Email address to check

        Returns:
            bool: True if user exists, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_username(self, username: str) -> bool:
        """
        Check if a user exists with the given username.

        Args:
            username: Username to check

        Returns:
            bool: True if user exists, False otherwise
        """
        pass

    @abstractmethod
    async def list_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        List users with pagination support.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List[User]: List of user entities
        """
        pass

    @abstractmethod
    async def count_users(self) -> int:
        """
        Count the total number of users in the repository.

        Returns:
            int: Total number of users
        """
        pass