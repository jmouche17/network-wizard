#!/bin/bash
# Network Wizard — Docker setup
# Usage: bash docker-setup.sh
# Run from inside the device-runner folder

set -e

echo ""
echo "================================================"
echo "  Network Wizard — Docker Setup"
echo "================================================"
echo ""

# ── check docker ──────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
    # add current user to docker group so sudo isn't needed
    sudo usermod -aG docker $USER
    echo "Docker installed. You may need to log out and back in for group changes."
else
    echo "✓ Docker found: $(docker --version)"
fi

if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null 2>&1; then
    # try older docker-compose
    if ! command -v docker-compose &>/dev/null; then
        echo "Installing docker-compose..."
        sudo apt-get install -y docker-compose-plugin 2>/dev/null || \
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose && sudo chmod +x /usr/local/bin/docker-compose
    fi
fi

# ── generate .env if it doesn't exist ────────────────────────────────────────
if [ ! -f .env ]; then
    echo "Generating secrets..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    # generate a valid Fernet key without needing the cryptography module
    # Fernet key = 32 random bytes, base64url encoded with padding
    ENC_KEY=$(python3 -c "
import os, base64
raw = os.urandom(32)
key = base64.urlsafe_b64encode(raw).decode()
print(key)
")
    cat > .env << EOF
SECRET_KEY=${SECRET_KEY}
ENC_KEY=${ENC_KEY}
# PORT=5000
EOF
    chmod 600 .env
    echo "✓ .env created with generated secrets"
else
    echo "✓ .env already exists — keeping existing secrets"
fi

# ── create data dirs ──────────────────────────────────────────────────────────
mkdir -p data scripts uploads backups logs
echo "✓ Data directories ready"

# ── build and start ───────────────────────────────────────────────────────────
echo ""
echo "Building and starting Network Wizard..."
docker compose up -d --build

echo ""
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "================================================"
echo "  Network Wizard is running!"
echo ""
echo "  URL:   http://$SERVER_IP"
echo "  Login: admin / admin"
echo ""
echo "  Change the default password immediately"
echo "  in the Users tab after logging in."
echo ""
echo "  Useful commands:"
echo "    docker compose logs -f          # live logs"
echo "    docker compose restart          # restart"
echo "    docker compose down             # stop"
echo "    docker compose up -d --build    # rebuild after update"
echo "================================================"
