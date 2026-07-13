# Network Wizard — Production Deployment Guide

## What's included

| File | Purpose |
|---|---|
| `setup.sh` | Automated setup script — runs everything below |
| `network-wizard.service` | systemd unit file |
| `network-wizard.nginx.conf` | nginx reverse proxy config |

---

## Quick start (automated)

```bash
# copy the project to your server
scp -r network-wizard/ user@yourserver:/tmp/

# ssh in and run setup
ssh user@yourserver
cd /tmp/network-wizard
sudo bash deploy/setup.sh your-domain.com
```

That's it. The script handles everything below automatically.

---

## Manual setup (step by step)

### 1. Create users

```bash
# App user — runs Flask/Gunicorn
useradd -r -m -d /opt/network-wizard -s /bin/false nwizard

# Script sandbox user — runs user scripts with minimal privileges
useradd -r -s /bin/false nwizard-scripts

# Allow nwizard to run scripts as nwizard-scripts (no password prompt)
echo "nwizard ALL=(nwizard-scripts) NOPASSWD: /usr/bin/python3, /bin/bash" >> /etc/sudoers
```

### 2. Deploy app

```bash
mkdir -p /opt/network-wizard
cp -r ./* /opt/network-wizard/
chown -R nwizard:nwizard /opt/network-wizard
chmod 700 /opt/network-wizard/data    # strict — contains encrypted keys
```

### 3. Python venv

```bash
sudo -u nwizard python3 -m venv /opt/network-wizard/venv
sudo -u nwizard /opt/network-wizard/venv/bin/pip install -r /opt/network-wizard/requirements.txt
```

### 4. Generate secrets

```bash
# Generate SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate ENC_KEY (Fernet key for encrypting device passwords/tokens)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy these values into the systemd service file (step 5).

### 5. Install systemd service

```bash
cp deploy/network-wizard.service /etc/systemd/system/

# Edit the service file and replace the placeholder secrets
nano /etc/systemd/system/network-wizard.service
# Set: Environment=SECRET_KEY=<your generated key>
# Set: Environment=ENC_KEY=<your generated fernet key>

chmod 600 /etc/systemd/system/network-wizard.service  # protect the secrets

systemctl daemon-reload
systemctl enable network-wizard
systemctl start network-wizard
```

Check it's running:
```bash
systemctl status network-wizard
journalctl -u network-wizard -f
```

### 6. nginx

```bash
apt install nginx certbot python3-certbot-nginx

# Add rate limit zones to /etc/nginx/nginx.conf inside the http {} block:
# limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
# limit_req_zone $binary_remote_addr zone=api:10m   rate=30r/m;

cp deploy/network-wizard.nginx.conf /etc/nginx/sites-available/network-wizard

# Edit and replace YOUR_DOMAIN_OR_IP and YOUR_DOMAIN
nano /etc/nginx/sites-available/network-wizard

ln -s /etc/nginx/sites-available/network-wizard /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
```

### 7. TLS certificate (Let's Encrypt)

```bash
certbot --nginx -d your-domain.com
# Certbot will edit nginx config automatically and set up auto-renewal
```

---

## Useful commands

```bash
# App status and logs
systemctl status network-wizard
journalctl -u network-wizard -f
tail -f /opt/network-wizard/logs/access.log
tail -f /opt/network-wizard/logs/error.log

# Restart after code changes
systemctl restart network-wizard

# nginx
nginx -t                        # test config
systemctl reload nginx          # reload without downtime

# Renew TLS cert (runs automatically via cron, but manual if needed)
certbot renew
```

---

## Security summary

| What | How |
|---|---|
| Secrets | `SECRET_KEY` and `ENC_KEY` in systemd env vars, never on filesystem |
| Device passwords/tokens | Fernet encrypted at rest in `data/devices.json` |
| User passwords | SHA-256 + salt hashed, never plaintext |
| Login brute force | Rate limited to 10 attempts/minute via flask-limiter + nginx |
| Script execution | Runs as `nwizard-scripts` (no shell, no home dir) via preexec_fn |
| Sessions | HTTPS-only cookies, HttpOnly, SameSite=Strict |
| Traffic | All HTTP redirected to HTTPS, TLS 1.2+ only |

---

## After deployment

1. Log in at `https://your-domain.com`
2. **Change the default admin password immediately** — Users tab → delete admin → add new admin with a strong password
3. Add your real devices
4. Upload scripts
