run:
	@echo "Gerando .env..."
	@echo "# Application Settings" > .env
	@echo "APP_APP_NAME=FIAP X Authentication Service" >> .env
	@echo "APP_APP_VERSION=1.0.0" >> .env
	@echo "APP_DEBUG=false" >> .env
	@echo "APP_HOST=0.0.0.0" >> .env
	@echo "APP_PORT=8000" >> .env
	@echo "APP_ENVIRONMENT=development" >> .env
	@echo "APP_LOG_LEVEL=INFO" >> .env
	@echo "APP_LOG_FORMAT=json" >> .env
	@echo "APP_WORKERS=1" >> .env
	@echo "" >> .env
	@echo "# Database Settings" >> .env
	@echo "DB_HOST=postgres" >> .env
	@echo "DB_PORT=5432" >> .env
	@echo "DB_NAME=fiap_x_auth" >> .env
	@echo "DB_USER=postgres" >> .env
	@echo "DB_PASSWORD=postgres123" >> .env
	@echo "DB_POOL_SIZE=20" >> .env
	@echo "DB_MAX_OVERFLOW=30" >> .env
	@echo "DB_ECHO=false" >> .env
	@echo "DB_POOL_PRE_PING=true" >> .env
	@echo "DB_POOL_RECYCLE=3600" >> .env
	@echo "DB_POOL_TIMEOUT=30" >> .env
	@echo "" >> .env
	@echo "# Redis Settings" >> .env
	@echo "REDIS_HOST=redis" >> .env
	@echo "REDIS_PORT=6379" >> .env
	@echo "REDIS_PASSWORD=redis123" >> .env
	@echo "REDIS_DB=0" >> .env
	@echo "REDIS_MAX_CONNECTIONS=50" >> .env
	@echo "REDIS_SOCKET_TIMEOUT=5" >> .env
	@echo "REDIS_SOCKET_CONNECT_TIMEOUT=5" >> .env
	@echo "" >> .env
	@echo "# JWT Settings" >> .env
	@echo "JWT_SECRET_KEY=your-super-secret-jwt-key-minimum-32-characters-long" >> .env
	@echo "JWT_ALGORITHM=HS256" >> .env
	@echo "JWT_ISSUER=fiap-x-auth" >> .env
	@echo "JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15" >> .env
	@echo "JWT_REFRESH_TOKEN_EXPIRE_DAYS=30" >> .env
	@echo "JWT_REMEMBER_ME_ACCESS_EXPIRE_MINUTES=30" >> .env
	@echo "JWT_REMEMBER_ME_REFRESH_EXPIRE_DAYS=90" >> .env
	@echo "" >> .env
	@echo "# Security Settings" >> .env
	@echo "SECURITY_BCRYPT_ROUNDS=12" >> .env
	@echo "SECURITY_CHECK_COMPROMISED_PASSWORDS=false" >> .env
	@echo "SECURITY_RATE_LIMIT_REQUESTS=100" >> .env
	@echo "SECURITY_RATE_LIMIT_WINDOW=60" >> .env
	@echo "SECURITY_CORS_ORIGINS=[\"*\"]" >> .env
	@echo "SECURITY_CORS_METHODS=[\"GET\", \"POST\", \"PUT\", \"DELETE\"]" >> .env
	@echo "SECURITY_CORS_HEADERS=[\"*\"]" >> .env
	@echo "" >> .env

	@echo "Iniciando docker compose up..."
	docker compose up
