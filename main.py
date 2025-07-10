from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import uvicorn

from infra.settings.settings import get_settings
from infra.databases.database_connection import DatabaseConnection
from api.auth_router import router as auth_router
from api.user_router import router as user_router
from api.user_router import router as user_router
from domain.exceptions import (
    AuthenticationException,
    UserNotFoundException,
    UserAlreadyExistsException,
    InvalidCredentialsException,
    WeakPasswordException,
    TokenExpiredException,
    InvalidTokenException
)

settings = get_settings()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events.

    Handles database connection initialization and cleanup,
    along with other application-level setup and teardown operations.
    """
    db_connection = DatabaseConnection(
        database_url=settings.database.url,
        echo=settings.database.echo
    )

    try:
        db_connection.initialize()
        logger.info("Database connection initialized")

        app.state.db_connection = db_connection

        yield

    finally:
        if hasattr(app.state, 'db_connection'):
            await app.state.db_connection.close()
            logger.info("Database connection closed")


app = FastAPI(
    title=settings.app.app_name,
    version=settings.app.app_version,
    description="FIAP X Authentication Service - Secure user authentication and management API",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.security.cors_origins,
    allow_credentials=True,
    allow_methods=settings.security.cors_methods,
    allow_headers=settings.security.cors_headers,
)

if settings.is_production:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]
    )


@app.exception_handler(AuthenticationException)
async def authentication_exception_handler(request: Request, exc: AuthenticationException):
    """Handle authentication-related exceptions."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "AUTHENTICATION_ERROR",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(UserNotFoundException)
async def user_not_found_exception_handler(request: Request, exc: UserNotFoundException):
    """Handle user not found exceptions."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "USER_NOT_FOUND",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(UserAlreadyExistsException)
async def user_already_exists_exception_handler(request: Request, exc: UserAlreadyExistsException):
    """Handle user already exists exceptions."""
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "USER_ALREADY_EXISTS",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(WeakPasswordException)
async def weak_password_exception_handler(request: Request, exc: WeakPasswordException):
    """Handle weak password exceptions."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "WEAK_PASSWORD",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(TokenExpiredException)
async def token_expired_exception_handler(request: Request, exc: TokenExpiredException):
    """Handle token expired exceptions."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "TOKEN_EXPIRED",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(InvalidTokenException)
async def invalid_token_exception_handler(request: Request, exc: InvalidTokenException):
    """Handle invalid token exceptions."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "INVALID_TOKEN",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    """Handle value error exceptions."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "message": str(exc),
            "error_code": "VALIDATION_ERROR",
            "data": None,
            "details": None
        }
    )


@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "Internal server error",
            "error_code": "SERVER_ERROR",
            "data": None,
            "details": None
        }
    )


app.include_router(auth_router)
app.include_router(user_router)


@app.get("/")
async def root():
    """
    Root endpoint providing API information.

    Returns basic information about the authentication service
    including version, status, and available endpoints.
    """
    return {
        "success": True,
        "message": f"Welcome to {settings.app.app_name}",
        "data": {
            "service": "FIAP X Authentication Service",
            "version": settings.app.app_version,
            "environment": settings.app.environment,
            "status": "operational",
            "endpoints": {
                "docs": "/docs",
                "auth": "/auth",
                "users": "/users",
                "health": "/health"
            }
        }
    }


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.

    Performs basic health checks including database connectivity
    and returns the service health status.
    """
    try:
        db_healthy = await app.state.db_connection.health_check()

        health_status = {
            "success": True,
            "message": "Service is healthy",
            "data": {
                "status": "healthy" if db_healthy else "degraded",
                "database": "connected" if db_healthy else "disconnected",
                "version": settings.app.app_version,
                "environment": settings.app.environment
            }
        }

        if not db_healthy:
            health_status["message"] = "Service is degraded"
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=health_status
            )

        return health_status

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "success": False,
                "message": "Service is unhealthy",
                "data": {
                    "status": "unhealthy",
                    "error": str(e)
                }
            }
        )


if __name__ == "__main__":
    """
    Run the application directly with uvicorn.

    This is primarily for development purposes.
    In production, use a proper ASGI server deployment.
    """
    uvicorn.run(
        "main:app",
        host=settings.app.host,
        port=settings.app.port,
        reload=settings.is_development,
        workers=1 if settings.is_development else settings.app.workers,
        log_level=settings.app.log_level.lower(),
        access_log=True
    )