from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """
    Database connection manager for PostgreSQL with async SQLAlchemy.

    This class manages the database connection lifecycle, session management,
    and provides connection pooling for optimal performance and resource usage.

    It implements the async context manager pattern for proper connection
    handling and ensures database sessions are properly closed after use.
    """

    def __init__(self, database_url: str, echo: bool = False):
        """
        Initialize database connection with the provided configuration.

        Args:
            database_url: PostgreSQL connection string
            echo: Whether to log SQL queries for debugging
        """
        self.database_url = database_url
        self.echo = echo
        self._engine = None
        self._session_factory = None

    def initialize(self) -> None:
        """
        Initialize the database engine and session factory.

        Creates the async engine with optimized connection pool settings
        and configures the session factory for dependency injection.
        """
        self._engine = create_async_engine(
            self.database_url,
            echo=self.echo,
            pool_size=20,
            max_overflow=30,
            pool_timeout=30,
            pool_recycle=3600,
            poolclass=NullPool if "sqlite" in self.database_url else None
        )

        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False
        )

        logger.info("Database connection initialized successfully")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Async context manager for database sessions.

        Provides a database session with automatic transaction management,
        ensuring proper cleanup and error handling.

        Yields:
            AsyncSession: Database session for executing queries

        Raises:
            Exception: Re-raises any database-related exceptions after rollback
        """
        if not self._session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {str(e)}")
                raise
            finally:
                await session.close()

    async def health_check(self) -> bool:
        """
        Perform a health check on the database connection.

        Tests the database connectivity by executing a simple query
        and returns the connection status.

        Returns:
            bool: True if database is accessible, False otherwise
        """
        try:
            from sqlalchemy import text
            async with self.get_session() as session:
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return False

    async def close(self) -> None:
        """
        Close the database engine and cleanup connections.

        Properly closes all database connections and cleans up
        the connection pool to prevent resource leaks.
        """
        if self._engine:
            await self._engine.dispose()
            logger.info("Database connection closed")

    @property
    def engine(self):
        """
        Get the database engine instance.

        Returns:
            AsyncEngine: SQLAlchemy async engine
        """
        return self._engine

    @property
    def session_factory(self):
        """
        Get the session factory for creating database sessions.

        Returns:
            async_sessionmaker: Session factory for creating database sessions
        """
        return self._session_factory