# Network Wizard — Windows Docker Setup
# Run from inside the device-runner folder:
#   Right-click PowerShell -> Run as Administrator, then:
#   cd C:\path\to\device-runner
#   .\docker-setup.ps1
#
# If you get an execution policy error, run first:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Network Wizard - Docker Setup (Windows)"       -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ── check Docker is installed ─────────────────────────────────────────────────
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "✓ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker not found. Please install Docker Desktop from:" -ForegroundColor Red
    Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    exit 1
}

# check Docker is actually running
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# ── generate .env if it doesn't exist ────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Write-Host "Generating secrets..." -ForegroundColor Yellow

    # generate SECRET_KEY — 32 random bytes as hex
    $secretBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($secretBytes)
    $secretKey = [System.BitConverter]::ToString($secretBytes).Replace("-", "").ToLower()

    # generate ENC_KEY — 32 random bytes as base64url (Fernet format)
    $encBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($encBytes)
    $encKey = [Convert]::ToBase64String($encBytes).Replace("+", "-").Replace("/", "_").TrimEnd("=")
    # Fernet requires padding to 44 chars
    while ($encKey.Length % 4 -ne 0) { $encKey += "=" }

    # write .env file
    @"
SECRET_KEY=$secretKey
ENC_KEY=$encKey
# PORT=5000
"@ | Set-Content -Path ".env" -Encoding UTF8

    Write-Host "✓ .env created with generated secrets" -ForegroundColor Green
} else {
    Write-Host "✓ .env already exists — keeping existing secrets" -ForegroundColor Green
}

# ── create data directories ───────────────────────────────────────────────────
$dirs = @("data", "scripts", "uploads", "backups", "logs")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
Write-Host "✓ Data directories ready" -ForegroundColor Green

# ── build and start ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Building and starting Network Wizard..." -ForegroundColor Yellow
Write-Host "(This may take a few minutes on first run)" -ForegroundColor Gray
Write-Host ""

docker compose up -d --build

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "✗ Docker build failed. Check the output above for errors." -ForegroundColor Red
    exit 1
}

# ── get local IP ──────────────────────────────────────────────────────────────
$localIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } |
    Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Network Wizard is running!" -ForegroundColor Green
Write-Host ""
Write-Host "  Local:    http://localhost:5000" -ForegroundColor White
if ($localIP) {
Write-Host "  Network:  http://${localIP}:5000" -ForegroundColor White
}
Write-Host ""
Write-Host "  Login:    admin / admin" -ForegroundColor White
Write-Host "  Change this immediately in the Users tab." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Gray
Write-Host "    docker compose logs -f          # live logs" -ForegroundColor Gray
Write-Host "    docker compose restart          # restart" -ForegroundColor Gray
Write-Host "    docker compose down             # stop" -ForegroundColor Gray
Write-Host "    docker compose up -d --build    # rebuild after update" -ForegroundColor Gray
Write-Host "================================================" -ForegroundColor Cyan
