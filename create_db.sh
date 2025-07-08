#!/bin/bash
# create_db.sh - Script to create database before running migrations

set -e

echo "Loading environment variables..."
export $(cat .env | grep -v '^#' | xargs)

echo "Waiting for PostgreSQL to be ready..."
until docker exec fiap_x_auth_postgres pg_isready -U ${DB_USER} -d postgres; do
    echo "Waiting for postgres..."
    sleep 2
done

echo "PostgreSQL is ready!"

echo "Creating database if it doesn't exist..."
docker exec fiap_x_auth_postgres psql -U ${DB_USER} -d postgres -tc "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'" | grep -q 1 || \
docker exec fiap_x_auth_postgres psql -U ${DB_USER} -d postgres -c "CREATE DATABASE ${DB_NAME};"

echo "Database ${DB_NAME} is ready!"

echo "Running migrations..."
docker-compose up migrations

echo "Database setup complete!"