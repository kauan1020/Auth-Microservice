# Authentication Microservice

Microserviço de autenticação e autorização de usuários, desenvolvido seguindo os princípios de Clean Architecture.

## Funcionalidades

- Registro de novos usuários
- Autenticação via email/username e senha
- Geração e validação de tokens JWT
- Refresh de tokens expirados
- Logout e revogação de tokens
- Perfil de usuário com atualização de dados
- Alteração de senha com validação
- Integração com serviços externos

## Arquitetura

O projeto segue Clean Architecture com separação clara de responsabilidades:

```
├── domain/              # Entidades e regras de negócio
├── use_cases/           # Casos de uso da aplicação
├── interfaces/          # Contratos e interfaces
├── infra/              # Implementações de infraestrutura
│   ├── controllers/     # Controllers HTTP
│   ├── repositories/    # Repositórios de dados
│   ├── services/        # Serviços externos
│   ├── gateways/        # Gateways para outros serviços
│   └── settings/        # Configurações da aplicação
└── tests/              # Testes unitários
```

## Tecnologias Utilizadas

- **Python 3.11+**
- **FastAPI** - Framework web
- **SQLAlchemy** - ORM para banco de dados
- **PostgreSQL** - Banco de dados principal
- **Redis** - Cache e sessões
- **JWT** - Tokens de autenticação
- **BCrypt** - Hash de senhas
- **Alembic** - Migrações de banco
- **Docker** - Containerização
- **Pytest** - Framework de testes

## Pré-requisitos

- Python 3.11 ou superior
- PostgreSQL
- Redis
- Docker e Docker Compose (para ambiente de desenvolvimento)

## Instalação

### Ambiente Local

1. Clone o repositório:
```bash
git clone <repository-url>
```

2. Crie um ambiente virtual:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate     # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```
4. Crie a network:
```bash
docker network create fiap_x_shared_network
```

5. Run:
```bash
make run
```
Swagger estará em http://localhost:8000/docs

## Configuração
### Variáveis de Ambiente

```bash
# Aplicação
APP_NAME="FIAP X Authentication Service"
APP_VERSION="1.0.0"
APP_ENVIRONMENT="development"
APP_DEBUG=true
APP_HOST="0.0.0.0"
APP_PORT=8000

# Banco de Dados
DATABASE_URL="postgresql+asyncpg://postgres:password@localhost:5432/auth_service"
DATABASE_HOST="localhost"
DATABASE_PORT=5432
DATABASE_NAME="auth_service"
DATABASE_USER="postgres"
DATABASE_PASSWORD="password"

# Redis
REDIS_URL="redis://localhost:6379/0"
REDIS_HOST="localhost"
REDIS_PORT=6379
REDIS_DB=0

# Segurança
SECRET_KEY="your-super-secret-key-change-in-production"
JWT_SECRET_KEY="your-jwt-secret-key"
JWT_ALGORITHM="HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Email (opcional)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USER="your-email@gmail.com"
SMTP_PASSWORD="your-app-password"
EMAIL_FROM="noreply@fiapx.com"

# CORS
CORS_ALLOWED_ORIGINS="http://localhost:3000,http://localhost:8080"
CORS_ALLOW_CREDENTIALS=true
```

## API Endpoints

### Registro de Usuário
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "SecurePassword123!",
  "first_name": "João",
  "last_name": "Silva"
}
```

### Login
```http
POST /auth/login
Content-Type: application/json

{
  "identifier": "user@example.com",
  "password": "SecurePassword123!",
  "remember_me": false
}
```

### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Validação de Token
```http
GET /auth/validate?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Logout
```http
POST /auth/logout
Authorization: Bearer <access_token>
```

### Perfil do Usuário
```http
GET /users/profile
Authorization: Bearer <access_token>
```

### Atualizar Perfil
```http
PUT /users/profile
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "first_name": "João",
  "last_name": "Santos",
  "username": "new_username"
}
```

### Alterar Senha
```http
POST /users/change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "current_password": "CurrentPassword123!",
  "new_password": "NewPassword123!",
  "confirm_password": "NewPassword123!"
}
```

### Health Check
```http
GET /health
```

## Estrutura do Token JWT

### Access Token
```json
{
  "sub": "user_id",
  "email": "user@example.com",
  "username": "username",
  "token_type": "access",
  "exp": 1234567890,
  "iat": 1234567890,
  "iss": "fiap-x-auth"
}
```

### Refresh Token
```json
{
  "sub": "user_id",
  "token_type": "refresh",
  "exp": 1234567890,
  "iat": 1234567890,
  "iss": "fiap-x-auth"
}
```

## Regras de Negócio

### Senhas
- Mínimo 8 caracteres
- Máximo 128 caracteres
- Deve conter ao menos: 1 maiúscula, 1 minúscula, 1 número, 1 caractere especial

### Usernames
- Mínimo 3 caracteres
- Máximo 30 caracteres
- Apenas letras, números, underscore e hífen

### Tokens
- Access Token: 15 minutos (30 minutos se remember_me=true)
- Refresh Token: 30 dias (90 dias se remember_me=true)
- Revogação automática de tokens existentes no login

## Testes

### Executar Todos os Testes
```bash
pytest
```

### Executar com Cobertura
```bash
pytest --cov --cov-report=html
```

### Executar Testes Específicos
```bash
pytest tests/test_auth_controller.py
pytest tests/use_cases/
pytest -k "test_register_user"
```

### Testes de Integração
```bash
pytest tests/integration/
```

## Monitoramento

### Logs
Os logs são estruturados em JSON e incluem:
- Request ID para rastreamento
- User ID quando aplicável
- Timestamps
- Níveis de log apropriados

### Métricas
- Taxa de sucesso/falha de autenticação
- Tempo de resposta dos endpoints
- Número de usuários ativos
- Tentativas de login falhadas

### Health Check
```bash
curl http://localhost:8000/health
```

## Segurança

### Boas Práticas Implementadas
- Hash seguro de senhas com BCrypt
- Tokens JWT com assinatura
- Rate limiting nos endpoints sensíveis
- Validação rigorosa de entrada
- Headers de segurança
- CORS configurado adequadamente

## Deploy

### Ambiente de Produção
```bash
# Build da imagem
docker build -t auth-service:latest .

# Execute com docker-compose
docker-compose -f docker-compose.prod.yml up -d
```

### Variáveis de Produção
- Use secrets manager
- Configure SSL/TLS
- Configure backup do banco
- Configure monitoring e alertas