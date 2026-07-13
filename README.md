# DeviceRunner

A web app for managing network devices and running Python scripts against their APIs.  
Built with Flask (backend) + vanilla HTML/JS (frontend).

---

## Project layout

```
device-runner/
├── app.py                  # Flask backend — all API routes
├── requirements.txt
├── static/
│   └── index.html          # Frontend (served by Flask)
├── scripts/                # Python script files (.py) — one per script
│   ├── ping_check.py
│   ├── get_interfaces.py
│   └── backup_config.py
└── data/                   # Persistent data (auto-created)
    ├── devices.json         # Device records (passwords Fernet-encrypted)
    ├── users.json           # User accounts (passwords SHA-256 + salt hashed)
    ├── scripts_meta.json    # Script metadata (name, desc, filename)
    ├── history.json         # Run history (last 500 entries)
    ├── .secret_key          # Flask session key (auto-generated, chmod 600)
    └── .enc_key             # Fernet encryption key (auto-generated, chmod 600)
```

---

## Quick start

### 1. Install dependencies

```bash
cd device-runner
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

Default credentials: `admin` / `admin` — change these immediately in the Users tab.

---

## Security notes

| Concern | How it's handled |
|---|---|
| Passwords at rest | Fernet symmetric encryption (`data/.enc_key`) |
| User passwords | SHA-256 + random salt, constant-time comparison |
| Sessions | Server-side Flask sessions signed with `data/.secret_key`, 8h TTL |
| Script execution | Subprocess with 30s timeout; runs as the same OS user as Flask |
| File permissions | `.secret_key` and `.enc_key` set to `chmod 600` on creation |

### For production deployment

- Run behind **nginx** or **gunicorn** (`gunicorn -w 4 app:app`)
- Enable **HTTPS** (Let's Encrypt / your cert)
- Set `app.config['SESSION_COOKIE_SECURE'] = True` and `SAMESITE='Strict'`
- **Restrict script execution** — consider running scripts in Docker containers or a dedicated sandbox user with limited OS permissions
- Rotate the `.enc_key` periodically (requires re-encrypting existing passwords)
- Back up `data/` — it contains all your device credentials

---

## Writing scripts

Scripts are plain `.py` files in the `scripts/` directory. When run, the backend injects two variables before execution:

```python
# device  — the single target device dict
# devices — the full dictionary of all devices

print(f"Connecting to {device['name']} at {device['ip']}:{device['port']}")
print(f"Protocol: {device['protocol']}, user: {device['username']}")

# Real connectivity example (Netmiko):
# from netmiko import ConnectHandler
# conn = ConnectHandler(
#     device_type='cisco_ios',
#     host=device['ip'],
#     port=device['port'],
#     username=device['username'],
#     password=device['password'],
# )
# output = conn.send_command('show version')
# conn.disconnect()
# print(output)
```

Scripts can import any installed Python package. Add packages to `requirements.txt` and reinstall.

---

## API reference

| Method | Path | Description |
|---|---|---|
| POST | `/api/login` | `{ username, password }` → session |
| POST | `/api/logout` | Clear session |
| GET  | `/api/me` | Current user info |
| GET  | `/api/devices` | All devices (passwords hidden) |
| POST | `/api/devices` | Create/update device |
| DELETE | `/api/devices/<name>` | Delete device |
| PATCH | `/api/devices/<name>/status` | Update status only |
| GET  | `/api/scripts` | All scripts with bodies |
| POST | `/api/scripts` | Create/update script |
| DELETE | `/api/scripts/<filename>` | Delete script + file |
| POST | `/api/run` | `{ filename, devices[] }` → run results |
| GET  | `/api/history` | Last 100 run records |
| GET  | `/api/dictionary` | Full device dict with decrypted passwords |
| GET  | `/api/users` | *(admin)* List users |
| POST | `/api/users` | *(admin)* Create user |
| DELETE | `/api/users/<username>` | *(admin)* Delete user |
