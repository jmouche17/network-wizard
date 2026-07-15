# Network Wizard - Windows Docker Setup
# Run from inside the device-runner folder:
#   cd C:\path\to\device-runner
#   .\docker-setup.ps1
#
# If you get an execution policy error, run first:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Network Wizard - Docker Setup (Windows)" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker is installed
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "OK Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Docker not found. Please install Docker Desktop from:" -ForegroundColor Red
    Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    exit 1
}

# Check Docker is running
docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}
Write-Host "OK Docker is running" -ForegroundColor Green

# Generate .env if it does not exist
$envPath = Join-Path (Get-Location) ".env"

if (Test-Path $envPath) {
    Write-Host "OK .env already exists - keeping existing secrets" -ForegroundColor Green
} else {
    Write-Host "Generating secrets..." -ForegroundColor Yellow

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    $secretBytes = New-Object byte[] 32
    $rng.GetBytes($secretBytes)
    $secretKey = [System.BitConverter]::ToString($secretBytes).Replace("-", "").ToLower()

    $encBytes = New-Object byte[] 32
    $rng.GetBytes($encBytes)
    $encKey = [Convert]::ToBase64String($encBytes)
    $encKey = $encKey.Replace("+", "-").Replace("/", "_").TrimEnd("=")
    while ($encKey.Length % 4 -ne 0) {
        $encKey = $encKey + "="
    }

    $line1 = "SECRET_KEY=" + $secretKey
    $line2 = "ENC_KEY=" + $encKey
    $envText = $line1 + [System.Environment]::NewLine + $line2 + [System.Environment]::NewLine
    [System.IO.File]::WriteAllText($envPath, $envText)

    Write-Host "OK .env created with generated secrets" -ForegroundColor Green
}

# Create data directories
$dirs = @("data", "scripts", "uploads", "backups", "logs")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
Write-Host "OK Data directories ready" -ForegroundColor Green

# Build and start
Write-Host ""
Write-Host "Building and starting Network Wizard..." -ForegroundColor Yellow
Write-Host "(This may take a few minutes on first run)" -ForegroundColor Gray
Write-Host ""

docker compose up -d --build

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Docker build failed. Check the output above for errors." -ForegroundColor Red
    exit 1
}

# Get local IP
$localIP = ""
$addresses = Get-NetIPAddress -AddressFamily IPv4
foreach ($addr in $addresses) {
    $ip = $addr.IPAddress
    if ($ip -notlike "127.*" -and $ip -notlike "169.*") {
        $localIP = $ip
        break
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Network Wizard is running!" -ForegroundColor Green
Write-Host ""
Write-Host "  Local:   http://localhost:5000" -ForegroundColor White
if ($localIP -ne "") {
    Write-Host "  Network: http://${localIP}:5000" -ForegroundColor White
}
Write-Host ""
Write-Host "  Login:   admin / admin" -ForegroundColor White
Write-Host "  Change the password immediately in the Users tab." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Gray
Write-Host "    docker compose logs -f         view live logs" -ForegroundColor Gray
Write-Host "    docker compose restart         restart the app" -ForegroundColor Gray
Write-Host "    docker compose down            stop the app" -ForegroundColor Gray
Write-Host "    docker compose up -d --build   rebuild after update" -ForegroundColor Gray
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
