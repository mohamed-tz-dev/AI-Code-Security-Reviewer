$ErrorActionPreference = "Stop"

$backendRoot = Split-Path -Parent $PSScriptRoot
Set-Location $backendRoot

New-Item -ItemType Directory -Force -Path ".docker" | Out-Null
$env:DOCKER_CONFIG = (Resolve-Path ".docker").Path

docker compose up -d
npm run migrate

Write-Host ""
Write-Host "Local services are ready."
Write-Host "Start the API with: npm run dev"
Write-Host "Start the worker with: npm run worker"
