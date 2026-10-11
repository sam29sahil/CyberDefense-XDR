#!/bin/bash
# =============================================================================
# CyberDefense XDR — Docker Entrypoint
# Supports local Docker Compose PostgreSQL and managed PostgreSQL (e.g. Neon).
# =============================================================================

set -e

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

echo "============================================"
echo "  CyberDefense XDR — Starting Application"
echo "============================================"

# Preserve a complete DATABASE_URL when supplied (recommended for managed DBs).
# Otherwise build one from the individual DB_* variables for Docker Compose.
if [ -z "${DATABASE_URL:-}" ] && [ -n "${DB_PASSWORD:-}" ]; then
    ENCODED_PW=$(python3 -c 'import urllib.parse, os; print(urllib.parse.quote_plus(os.getenv("DB_PASSWORD", "")))')
    DATABASE_URL="postgresql://${DB_USER:-cyberadmin}:${ENCODED_PW}@${DB_HOST:-db}:${DB_PORT:-5432}/${DB_NAME:-cyberdefense_xdr}"
    if [ -n "${DB_SSLMODE:-}" ]; then
        DATABASE_URL="${DATABASE_URL}?sslmode=${DB_SSLMODE}"
    fi
    export DATABASE_URL
fi

# Wait for PostgreSQL only when a discrete DB_HOST is configured (e.g. Compose).
# Managed database URLs are checked by the migration step, avoiding pg_isready
# assumptions about pooled endpoints.
if [ -n "${DB_HOST:-}" ]; then
    echo "[entrypoint] Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT:-5432}..."
    MAX_RETRIES=30
    RETRY_COUNT=0
    until pg_isready -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-cyberadmin}" -q 2>/dev/null; do
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
            echo "[entrypoint] ERROR: PostgreSQL not available after ${MAX_RETRIES} attempts. Exiting."
            exit 1
        fi
        echo "[entrypoint] PostgreSQL not ready yet (attempt ${RETRY_COUNT}/${MAX_RETRIES})..."
        sleep 2
    done
    echo "[entrypoint] PostgreSQL is ready."
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "[entrypoint] ERROR: Set DATABASE_URL or DB_PASSWORD/DB_HOST/DB_NAME/DB_USER."
    exit 1
fi

echo "[entrypoint] Running database migrations..."
flask --app run.py db upgrade
echo "[entrypoint] Migrations complete."

echo "[entrypoint] Ensuring instance directories exist..."
mkdir -p instance/pcap_uploads instance/ids instance/reports
chmod 750 instance/pcap_uploads
echo "[entrypoint] Instance directories ready."

PORT_TO_USE="${PORT:-${APP_PORT:-5000}}"
echo "[entrypoint] Starting Gunicorn on port ${PORT_TO_USE}..."
exec gunicorn \
    --bind "0.0.0.0:${PORT_TO_USE}" \
    --workers "${GUNICORN_WORKERS:-3}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --access-logfile "-" \
    --error-logfile "-" \
    --log-level "info" \
    "run:app"
