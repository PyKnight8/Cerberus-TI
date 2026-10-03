#!/usr/bin/env bash
set -euo pipefail

SERVER="${1:-}"
USER_NAME="${2:-$USER}"
REMOTE_DIR="${3:-/opt/cerberus-ti}"
PORT="${CERBERUS_PORT:-8180}"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="${TMPDIR:-/tmp}/cerberus-ti-${STAMP}.tar.gz"
REMOTE_ARCHIVE="/tmp/cerberus-ti-${STAMP}.tar.gz"

if [[ -z "$SERVER" ]]; then
    echo "Usage: $0 <server> [ssh-user] [remote-dir]"
    echo "Example: $0 192.168.88.247 ibrahim /opt/cerberus-ti"
    exit 1
fi

HEALTH_URL="${CERBERUS_HEALTH_URL:-http://${SERVER}:${PORT}/lists/domains.txt}"

for cmd in ssh scp tar curl; do
    command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd"; exit 1; }
done

cleanup() {
    rm -f "$ARCHIVE"
}
trap cleanup EXIT

echo "[+] Cerberus-TI deployment"
echo "    Target: ${USER_NAME}@${SERVER}"
echo "    Remote: ${REMOTE_DIR}"

echo "[+] Packaging source..."
tar -C "$PROJECT_DIR" -czf "$ARCHIVE" \
    --exclude='.git' \
    --exclude='.github' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='.pytest_cache' \
    --exclude='.ruff_cache' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='data' \
    --exclude='tests' \
    --exclude='GISEC_AI_Cybersecurity_v2.pptx' \
    .

echo "[+] Uploading release..."
scp "$ARCHIVE" "${USER_NAME}@${SERVER}:${REMOTE_ARCHIVE}"

echo "[+] Deploying remotely..."
ssh "${USER_NAME}@${SERVER}" bash -s -- "$REMOTE_DIR" "$REMOTE_ARCHIVE" "$STAMP" <<'REMOTE'
set -euo pipefail

REMOTE_DIR="$1"
ARCHIVE="$2"
STAMP="$3"

command -v docker >/dev/null || { echo "Docker is not installed."; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose plugin is unavailable."; exit 1; }

mkdir -p "$REMOTE_DIR"
cd "$REMOTE_DIR"
mkdir -p geoip

DEPLOY_ROOT="$REMOTE_DIR/.deploy"
STAGE="$DEPLOY_ROOT/stage-${STAMP}"
BACKUP="$DEPLOY_ROOT/backup-${STAMP}"
mkdir -p "$STAGE" "$BACKUP"
tar -xzf "$ARCHIVE" -C "$STAGE"

[ -f .env ] && cp -a .env "$STAGE/.env"
[ -d geoip ] && { rm -rf "$STAGE/geoip"; cp -a geoip "$STAGE/geoip"; }

echo "[+] Building candidate image..."
cd "$STAGE"
docker compose build

echo "[+] Replacing application files..."
mkdir -p "$BACKUP"
cd "$REMOTE_DIR"
find . -mindepth 1 -maxdepth 1 ! -name '.env' ! -name 'geoip' ! -name '.deploy' -exec mv {} "$BACKUP/" \;

cd "$STAGE"
find . -mindepth 1 -maxdepth 1 ! -name '.env' ! -name 'geoip' -exec mv {} "$REMOTE_DIR/" \;

cd "$REMOTE_DIR"
rm -rf "$STAGE"

echo "[+] Recreating Cerberus..."
docker compose up -d --remove-orphans
docker compose ps

rm -f "$ARCHIVE"
echo "[+] Previous release retained temporarily at: $BACKUP"
echo "    Remove it after verifying the deployment."
REMOTE

echo "[+] Checking domains endpoint..."
sleep 3
if curl --fail --silent --show-error --max-time 15 "$HEALTH_URL" >/dev/null; then
    echo "[+] Deployment healthy: $HEALTH_URL"
else
    echo "[!] Deployment completed, but the health check failed."
    echo "    Check: ssh ${USER_NAME}@${SERVER} 'cd ${REMOTE_DIR} && docker compose logs --tail=100'"
    exit 2
fi
