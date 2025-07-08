from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Optional
import os
from functools import lru_cache


class DatabaseSettings(BaseSettings):
    """
    Database configuration settings.

    Contains all database-related configuration parameters including
    connection settings, pool configuration, and database-specific options.
    """

    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, description="Database port")
    name: str = Field(default="fiap_x_auth", description="Database name")
    user: str = Field(default="postgres", description="Database user")
    password: str = Field(default="", description="Database password")

    pool_size: int = Field(default=5, description="Connection pool size")
    max_overflow: int = Field(default=10, description="Max pool overflow")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")
    pool_recycle: int = Field(default=3600, description="Pool recycle time in seconds")
    pool_pre_ping: bool = Field(default=True, description="Enable pool pre-ping")

    echo: bool = Field(default=False, description="Enable SQL query logging")

    class Config:
        env_prefix = "DB_"
        case_sensitive = False

    @property
    def url(self) -> str:
        """
        Generate database connection URL for AsyncPG.

        Returns:
            str: PostgreSQL connection string with asyncpg driver
        """
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def sync_url(self) -> str:
        """
        Generate synchronous database connection URL for migrations.

        Returns:
            str: PostgreSQL connection string with psycopg2 driver
        """
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @validator('port')
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v


class RedisSettings(BaseSettings):
    """
    Redis configuration settings.

    Contains Redis connection parameters for caching, session storage,
    and messaging operations.
    """

    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, description="Redis port")
    password: Optional[str] = Field(default=None, description="Redis password")
    db: int = Field(default=0, description="Redis database number")

    max_connections: int = Field(default=50, description="Max connection pool size")
    socket_timeout: int = Field(default=5, description="Socket timeout in seconds")
    socket_connect_timeout: int = Field(default=5, description="Connection timeout in seconds")

    class Config:
        env_prefix = "REDIS_"
        case_sensitive = False

    @property
    def url(self) -> str:
        """
        Generate Redis connection URL.

        Returns:
            str: Redis connection string
        """
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"

    @validator('port')
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v

    @validator('db')
    def validate_db(cls, v):
        if not 0 <= v <= 15:
            raise ValueError('Redis DB must be between 0 and 15')
        return v


class JWTSettings(BaseSettings):
    """
    JWT token configuration settings.

    Contains JWT-related configuration including secret keys, algorithms,
    and token expiration times.
    """

    secret_key: str = Field(default="your-secret-key-here-must-be-at-least-32-characters-long", description="JWT secret key for signing tokens")
    algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    issuer: str = Field(default="fiap-x-auth", description="JWT token issuer")

    access_token_expire_minutes: int = Field(default=15, description="Access token expiration in minutes")
    refresh_token_expire_days: int = Field(default=30, description="Refresh token expiration in days")
    remember_me_access_expire_minutes: int = Field(default=30, description="Remember me access token expiration")
    remember_me_refresh_expire_days: int = Field(default=90, description="Remember me refresh token expiration")

    class Config:
        env_prefix = "JWT_"
        case_sensitive = False

    @validator('secret_key')
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError('JWT secret key must be at least 32 characters long')
        return v

    @validator('algorithm')
    def validate_algorithm(cls, v):
        allowed_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
        if v not in allowed_algorithms:
            raise ValueError(f'Algorithm must be one of: {", ".join(allowed_algorithms)}')
        return v


class SecuritySettings(BaseSettings):
    """
    Security configuration settings.

    Contains security-related configuration including password policies,
    rate limiting, and security headers.
    """

    bcrypt_rounds: int = Field(default=12, description="Bcrypt hashing rounds")
    check_compromised_passwords: bool = Field(default=False, description="Check passwords against breach databases")

    rate_limit_requests: int = Field(default=100, description="Rate limit requests per minute")
    rate_limit_window: int = Field(default=60, description="Rate limit window in seconds")

    cors_origins: list = Field(default=["*"], description="CORS allowed origins")
    cors_methods: list = Field(default=["GET", "POST", "PUT", "DELETE"], description="CORS allowed methods")
    cors_headers: list = Field(default=["*"], description="CORS allowed headers")

    class Config:
        env_prefix = "SECURITY_"
        case_sensitive = False

    @validator('bcrypt_rounds')
    def validate_bcrypt_rounds(cls, v):
        if not 4 <= v <= 31:
            raise ValueError('Bcrypt rounds must be between 4 and 31')
        return v


class ApplicationSettings(BaseSettings):
    """
    Main application configuration settings.

    Contains general application settings including server configuration,
    logging, and feature flags.
    """

    app_name: str = Field(default="FIAP X Authentication Service", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Enable debug mode")

    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    workers: int = Field(default=1, description="Number of worker processes")

    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format (json or text)")

    environment: str = Field(default="development", description="Application environment")

    class Config:
        env_prefix = "APP_"
        case_sensitive = False

    @validator('log_level')
    def validate_log_level(cls, v):
        allowed_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in allowed_levels:
            raise ValueError(f'Log level must be one of: {", ".join(allowed_levels)}')
        return v.upper()

    @validator('environment')
    def validate_environment(cls, v):
        allowed_envs = ['development', 'testing', 'staging', 'production']
        if v.lower() not in allowed_envs:
            raise ValueError(f'Environment must be one of: {", ".join(allowed_envs)}')
        return v.lower()


class Settings(BaseSettings):
    """
    Main settings container that combines all configuration sections.

    This class serves as the main configuration entry point, combining
    all individual setting classes into a single configuration object.
    """

    # Declare sub-settings as class attributes with proper initialization
    app: ApplicationSettings = Field(default_factory=ApplicationSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)

    class Config:
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"

    @property
    def is_production(self) -> bool:
        """
        Check if application is running in production environment.

        Returns:
            bool: True if running in production, False otherwise
        """
        return self.app.environment == "production"

    @property
    def is_development(self) -> bool:
        """
        Check if application is running in development environment.

        Returns:
            bool: True if running in development, False otherwise
        """
        return self.app.environment == "development"


@lru_cache()
def get_settings() -> Settings:
    """
    Factory function to create and return application settings.

    Uses LRU cache to ensure settings are loaded only once and reused
    across the application lifecycle, preventing configuration reload issues.

    Returns:
        Settings: Configured application settings instance (cached)
    """
    return Settings()