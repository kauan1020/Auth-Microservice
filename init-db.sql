-- init-db.sql
-- This script ensures the database exists and has the correct permissions

-- Create database if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'fiap_x_auth') THEN
        CREATE DATABASE fiap_x_auth;
    END IF;
END
$$;

-- Grant all privileges on database to the user
GRANT ALL PRIVILEGES ON DATABASE fiap_x_auth TO postgres;

-- Create extensions if needed (run this after connecting to the database)
\c fiap_x_auth;

-- Create UUID extension if you need it for your tables
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create other extensions as needed
-- CREATE EXTENSION IF NOT EXISTS "pg_trgm";
-- CREATE EXTENSION IF NOT EXISTS "btree_gin";