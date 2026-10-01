$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "Cerberus-TI is not set up yet." -ForegroundColor Red
    Write-Host "Run:"
    Write-Host "  .\setup.ps1"
    exit 1
}

Write-Host "=== Starting Cerberus-TI ===" -ForegroundColor Cyan
Write-Host "Dashboard: http://127.0.0.1:8080/admin"
Write-Host ""

& $Python -m uvicorn app.main:app `
    --host 127.0.0.1 `
    --port 8080 `
    --workers 1