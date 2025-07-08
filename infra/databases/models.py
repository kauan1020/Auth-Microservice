from sqlalchemy import Column, String, DateTime, Boolean, Enum, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
import enum

Base = declarative_base()


class UserStatusEnum(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BLOCKED = "blocked"


class TokenTypeEnum(enum.Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class UserModel(Base):
    """
    SQLAlchemy model for user data persistence.

    This model represents the users table structure in PostgreSQL database,
    mapping domain User entities to relational database records.

    The model includes all necessary fields for user management, authentication,
    and audit trail functionality with proper indexing for performance.
    """

    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    status = Column(Enum(UserStatusEnum), nullable=False, default=UserStatusEnum.ACTIVE)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"


class TokenModel(Base):
    """
    SQLAlchemy model for authentication token persistence.

    This model represents the auth_tokens table structure for storing
    JWT token metadata, enabling token validation, revocation, and cleanup.

    The model supports both access and refresh tokens with proper expiration
    handling and revocation mechanisms for security management.
    """

    __tablename__ = "auth_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(Text, nullable=False, unique=True, index=True)
    token_type = Column(Enum(TokenTypeEnum), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    is_revoked = Column(Boolean, nullable=False, default=False, index=True)

    def __repr__(self):
        return f"<Token(id={self.id}, type={self.token_type}, user_id={self.user_id})>"