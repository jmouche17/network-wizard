#!/bin/bash
# Network Wizard — server setup script
# Run as root on Ubuntu 22.04 / Debian 12
# Usage: sudo bash deploy/setup.sh [your-domain.com]
#
# Run from inside the extracted project folder:
#   cd device-runner
#   sudo bash deploy/setup.sh your-domain.com

set -e

DOMAIN=${1:-""}
APP_DIR="/opt/network-wizard"
APP_USER="nwizard"
SCRIPT_USER="nwizard-scripts"

# ── check root ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash deploy/setup.sh [domain]"
    exit 1
fi

echo ""
echo "================================================"
echo "  Network Wizard — Production Setup"
echo "================================================"
echo ""

# ── system packages ───────────────────────────────────────────────────────────
echo "[1/8] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

# ── users ─────────────────────────────────────────────────────────────────────
echo "[2/8] Creating service users..."
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -m -d "$APP_DIR" -s /bin/false "$APP_USER"
    echo "  Created: $APP_USER"
fi
if ! id "$SCRIPT_USER" &>/dev/null; then
    useradd -r -s /bin/false "$SCRIPT_USER"
    echo "  Created: $SCRIPT_USER"
fi
if ! grep -q "$SCRIPT_USER" /etc/sudoers 2>/dev/null; then
    echo "$APP_USER ALL=($SCRIPT_USER) NOPASSWD: /usr/bin/python3, /bin/bash" >> /etc/sudoers
    echo "  Added sudoers rule"
fi

# ── deploy files ──────────────────────────────────────────────────────────────
echo "[3/8] Deploying to $APP_DIR..."
mkdir -p "$APP_DIR"/{data,scripts,uploads,logs,backups,static}
cp app.py "$APP_DIR/"
cp requirements.txt "$APP_DIR/"
cp static/index.html "$APP_DIR/static/"
cp -r scripts/* "$APP_DIR/scripts/" 2>/dev/null || true
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 700 "$APP_DIR/data"
chmod 755 "$APP_DIR/static" "$APP_DIR/uploads" "$APP_DIR/scripts"

# ── python venv ───────────────────────────────────────────────────────────────
echo "[4/8] Setting up Python venv..."
sudo -u "$APP_USER" python3 -m venv "$APP_DIR/venv"
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install -q --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
echo "  Done"

# ── generate secrets ──────────────────────────────────────────────────────────
echo "[5/8] Generating secrets..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ENC_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
echo "  Generated SECRET_KEY and ENC_KEY"

# ── systemd service ───────────────────────────────────────────────────────────
echo "[6/8] Installing systemd service..."
SERVICE_FILE="/etc/systemd/system/network-wizard.service"
cp deploy/network-wizard.service "$SERVICE_FILE"
sed -i "s|REPLACE_WITH_RANDOM_SECRET|$SECRET_KEY|g" "$SERVICE_FILE"
sed -i "s|REPLACE_WITH_FERNET_KEY|$ENC_KEY|g"       "$SERVICE_FILE"
chmod 600 "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable network-wizard
echo "  Service installed"

# ── nginx ─────────────────────────────────────────────────────────────────────
echo "[7/8] Configuring nginx..."
# add rate limit zones if not already present
if ! grep -q "zone=login" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\\n\tlimit_req_zone $binary_remote_addr zone=login:10m rate=5r\/m;\n\tlimit_req_zone $binary_remote_addr zone=api:10m   rate=30r\/m;' /etc/nginx/nginx.conf
fi

cp deploy/network-wizard.nginx.conf /etc/nginx/sites-available/network-wizard

if [ -n "$DOMAIN" ]; then
    sed -i "s/YOUR_DOMAIN_OR_IP/$DOMAIN/g" /etc/nginx/sites-available/network-wizard
    sed -i "s/YOUR_DOMAIN/$DOMAIN/g"       /etc/nginx/sites-available/network-wizard
else
    # no domain — use HTTP only config
    cat > /etc/nginx/sites-available/network-wizard << NGINX
server {
    listen 80;
    server_name _;
    client_max_body_size 6M;

    location /api/login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /socket.io/ {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    \$http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       \$host;
        proxy_read_timeout 3600s;
    }

    location /api/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 125s;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NGINX
    echo "  No domain — using HTTP only on port 80"
fi

ln -sf /etc/nginx/sites-available/network-wizard /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && echo "  nginx config OK"

# ── TLS cert ──────────────────────────────────────────────────────────────────
if [ -n "$DOMAIN" ]; then
    echo "[8/8] Obtaining TLS certificate for $DOMAIN..."
    # start nginx in HTTP-only mode first for ACME challenge
    sed -i 's/listen 443 ssl/listen 443/' /etc/nginx/sites-available/network-wizard
    sed -i '/ssl_/d' /etc/nginx/sites-available/network-wizard
    systemctl restart nginx
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" || {
        echo "  certbot failed — run manually: certbot --nginx -d $DOMAIN"
    }
else
    echo "[8/8] Skipping TLS — no domain provided"
fi

# ── start ─────────────────────────────────────────────────────────────────────
systemctl start network-wizard
systemctl restart nginx

echo ""
echo "================================================"
echo "  Setup complete!"
echo ""
if [ -n "$DOMAIN" ]; then
    echo "  URL: https://$DOMAIN"
else
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo "  URL: http://$SERVER_IP"
fi
echo ""
echo "  Login: admin / admin"
echo "  Change this immediately in the Users tab."
echo ""
echo "  Commands:"
echo "    systemctl status network-wizard"
echo "    journalctl -u network-wizard -f"
echo "    tail -f $APP_DIR/logs/error.log"
echo "================================================"
