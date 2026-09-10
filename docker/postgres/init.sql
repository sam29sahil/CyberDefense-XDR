-- =============================================================================
-- CyberDefense XDR — PostgreSQL Initialization
-- =============================================================================
-- This script runs when the PostgreSQL container is first initialized.
-- It creates the application database and user if they do not already exist.
-- =============================================================================

-- Note: The POSTGRES_DB, POSTGRES_USER, and POSTGRES_PASSWORD environment
-- variables in docker-compose.yml handle the primary database and user creation.
-- This script exists for any additional initialization if needed.

-- Grant full privileges on the database to the application user
-- (this is handled automatically by POSTGRES_USER in the official image)

-- Ensure the uuid-ossp extension is available for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

