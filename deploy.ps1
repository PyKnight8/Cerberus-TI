[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [string]$User = $env:USERNAME,
    [string]$RemoteDir = "/opt/cerberus-ti",
    [string]$HealthUrl = "",
    [int]$Port = 8180
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Archive = Join-Path $env:TEMP "cerberus-ti-$Stamp.tar.gz"
$RemoteArchive = "/tmp/cerberus-ti-$Stamp.tar.gz"

if (-not $HealthUrl) {
    $HealthUrl = "http://${Server}:${Port}/lists/domains.txt"
}

Write-Host "[+] Cerberus-TI deployment"
Write-Host "    Target: ${User}@${Server}"
Write-Host "    Remote: $RemoteDir"

foreach ($cmd in @("ssh", "scp", "tar")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Required command '$cmd' was not found."
    }
}

Push-Location $ProjectDir
try {
    Write-Host "[+] Packaging source..."
    tar -czf $Archive `
        --exclude=".git" `
        --exclude=".github" `
        --exclude=".venv" `
        --exclude="venv" `
        --exclude="__pycache__" `
        --exclude=".pytest_cache" `
        --exclude=".ruff_cache" `
        --exclude="*.pyc" `
        --exclude=".env" `
        --exclude="data" `
        --exclude="tests" `
        --exclude="GISEC_AI_Cybersecurity_v2.pptx" `
        .
    if ($LASTEXITCODE -ne 0) { throw "Failed to create archive." }

    Write-Host "[+] Uploading release..."
    scp $Archive "${User}@${Server}:$RemoteArchive"
    if ($LASTEXITCODE -ne 0) { throw "SCP failed." }

    Write-Host "[+] Deploying remotely..."
    $remoteScript = @'
set -euo pipefail

REMOTE_DIR="$1"
ARCHIVE="$2"
STAMP="$3"

command -v docker >/dev/null || { echo "Docker is not installed."; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose plugin is unavailable."; exit 1; }

mkdir -p "$REMOTE_DIR"
cd "$REMOTE_DIR"

# Keep server-owned state/configuration outside release replacement.
mkdir -p geoip

DEPLOY_ROOT="$REMOTE_DIR/.deploy"
STAGE="$DEPLOY_ROOT/stage-${STAMP}"
BACKUP="$DEPLOY_ROOT/backup-${STAMP}"
mkdir -p "$STAGE" "$BACKUP"
tar -xzf "$ARCHIVE" -C "$STAGE"

# Preserve deployment-specific files/directories.
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

echo "[+] Container status:"
docker compose ps

rm -f "$ARCHIVE"
echo "[+] Previous release retained temporarily at: $BACKUP"
echo "    Remove it after verifying the deployment."
'@

    $remoteScript = $remoteScript -replace "`r", ""
    $remoteScript | ssh "${User}@${Server}" "bash -s -- '$RemoteDir' '$RemoteArchive' '$Stamp'"
    if ($LASTEXITCODE -ne 0) { throw "Remote deployment failed." }

    Write-Host "[+] Checking domains endpoint..."
    Start-Sleep -Seconds 3
    try {
        $response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 15
        if ($response.StatusCode -ne 200) {
            throw "HTTP $($response.StatusCode)"
        }
        Write-Host "[+] Deployment healthy: $HealthUrl"
    }
    catch {
        Write-Warning "Deployment completed, but health check failed: $($_.Exception.Message)"
        Write-Warning "Check: ssh ${User}@${Server} 'cd $RemoteDir && docker compose logs --tail=100'"
        exit 2
    }
}
finally {
    Pop-Location
    Remove-Item $Archive -Force -ErrorAction SilentlyContinue
}
