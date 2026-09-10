#!/bin/bash
# =============================================================================
# CyberDefense XDR — Docker Entrypoint
# =============================================================================
# Waits for PostgreSQL, runs database migrations, then starts Gunicorn.
# =============================================================================

set -e

# If arguments were passed to the container, execute them directly
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

echo "============================================"
echo "  CyberDefense XDR — Starting Application"
echo "============================================"

# Ensure DATABASE_URL has properly URL-encoded credentials
if [ -n "$DB_PASSWORD" ]; then
    ENCODED_PW=$(python3 -c 'import urllib.parse, os; print(urllib.parse.quote_plus(os.getenv("DB_PASSWORD", "")))')
    export DATABASE_URL="postgresql://${DB_USER:-cyberadmin}:${ENCODED_PW}@${DB_HOST:-db}:${DB_PORT:-5432}/${DB_NAME:-cyberdefense_xdr}"
fi

# ---------------------------------------------------------------------------
# 1. Wait for PostgreSQL to be ready
# ---------------------------------------------------------------------------
echo "[entrypoint] Waiting for PostgreSQL at ${DB_HOST:-db}:${DB_PORT:-5432}..."

MAX_RETRIES=30
RETRY_COUNT=0

until pg_isready -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "${DB_USER:-cyberadmin}" -q 2>/dev/null; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
        echo "[entrypoint] ERROR: PostgreSQL not available after ${MAX_RETRIES} attempts. Exiting."
        exit 1
    fi
    echo "[entrypoint] PostgreSQL not ready yet (attempt ${RETRY_COUNT}/${MAX_RETRIES})..."
    sleep 2
done

echo "[entrypoint] PostgreSQL is ready."

# ---------------------------------------------------------------------------
# 2. Run database migrations
# ---------------------------------------------------------------------------
echo "[entrypoint] Running database migrations..."
flask --app run.py db upgrade
echo "[entrypoint] Migrations complete."

# ---------------------------------------------------------------------------
# 3. Create instance directories (writable storage)
# ---------------------------------------------------------------------------
echo "[entrypoint] Ensuring instance directories exist..."
mkdir -p instance/pcap_uploads instance/ids instance/reports
chmod 750 instance/pcap_uploads
echo "[entrypoint] Instance directories ready."

# ---------------------------------------------------------------------------
# 4. Start Gunicorn WSGI server
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting Gunicorn..."
echo "============================================"

exec gunicorn \
    --bind "0.0.0.0:${APP_PORT:-5000}" \
    --workers "${GUNICORN_WORKERS:-3}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --access-logfile "-" \
    --error-logfile "-" \
    --log-level "info" \
    "run:app"

