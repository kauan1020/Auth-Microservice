import asyncio
from logging.config import fileConfig
from sqlalchemy import pool, create_engine
from sqlalchemy.engine import Connection
from alembic import context
import os
import sys

# Adicionar o diretório pai ao path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Imports dos models
from infra.databases.models import Base

# Configuração do Alembic
config = context.config

# Interpretar o arquivo de configuração para logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadados das tabelas
target_metadata = Base.metadata


def get_url():
    """
    Constrói a URL do banco a partir das variáveis de ambiente.
    Para migrations, usar psycopg2 (síncrono).
    """
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    name = os.getenv("DB_NAME", "fiap_x_auth")
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASSWORD", "postgres123")

    # Para migrações, usar psycopg2 (síncrono)
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def run_migrations_offline() -> None:
    """
    Executar migrações em modo 'offline'.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """
    Executar migrações com uma conexão existente.
    """
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Executar migrações em modo 'online' com engine síncrono.
    """
    # Usar engine síncrono para migrations
    connectable = create_engine(
        get_url(),
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()