"""
Network Wizard — Flask backend
Handles auth, device CRUD, script management, groups, file uploads, sandboxed execution,
network tools (ping/traceroute/DNS/port scan), scheduling, config backup viewer,
SSH live terminal (SocketIO + Paramiko), and TOTP MFA.
"""

import os, json, hashlib, hmac, secrets, subprocess, sys, tempfile, pwd, grp
import socket, platform, threading, difflib, io, base64
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, session, Response, stream_with_context, redirect, url_for
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

# ── optional imports ──────────────────────────────────────────────────────────
try:
    from flask_socketio import SocketIO, emit, disconnect
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import pyotp, qrcode
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

# ── paths ─────────────────────────────────────────────────────────────────────
BASE      = Path(__file__).parent
DATA      = BASE / "data"
SCRIPTS   = BASE / "scripts"
STATIC    = BASE / "static"
UPLOADS   = BASE / "uploads"
LOGS      = BASE / "logs"
BACKUPS   = BASE / "backups"

for d in (DATA, SCRIPTS, UPLOADS, LOGS, BACKUPS):
    d.mkdir(exist_ok=True)

DEVICES_FILE   = DATA / "devices.json"
USERS_FILE     = DATA / "users.json"
HISTORY_FILE   = DATA / "history.json"
GROUPS_FILE    = DATA / "groups.json"
ENV_VARS_FILE  = DATA / "env_vars.json"
SCHEDULES_FILE = DATA / "schedules.json"
WEBHOOKS_FILE  = DATA / "webhooks.json"
UDF_CONFIG_FILE = DATA / "udf_config.json"
KEY_FILE       = DATA / ".secret_key"
ENC_KEY_FILE   = DATA / ".enc_key"

MAX_UDF_FIELDS = 10  # maximum number of user-defined fields per device

ALLOWED_EXTENSIONS = {'.txt', '.csv', '.json', '.yaml', '.yml', '.j2', '.conf', '.cfg', '.log', '.xml'}
MAX_UPLOAD_BYTES   = 5 * 1024 * 1024  # 5 MB

# ── sandbox user for script execution ─────────────────────────────────────────
# Scripts run as this low-privilege OS user instead of the Flask process user.
# Created by setup.sh — if it doesn't exist, scripts run as the current user.
SCRIPT_SANDBOX_USER = os.environ.get("SCRIPT_SANDBOX_USER", "nwizard-scripts")

def get_sandbox_uid_gid():
    """Return (uid, gid) for the sandbox user, or (None, None) if not found."""
    try:
        pw = pwd.getpwnam(SCRIPT_SANDBOX_USER)
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        return None, None

# ── encryption ────────────────────────────────────────────────────────────────
def load_or_create_key(path, generator):
    if path.exists():
        return path.read_bytes()
    key = generator()
    path.write_bytes(key)
    path.chmod(0o600)
    return key

# Prefer environment variables (production) — fall back to file-based keys (dev)
_env_secret = os.environ.get("SECRET_KEY")
_env_enc    = os.environ.get("ENC_KEY")

SECRET_KEY = _env_secret.encode() if _env_secret else load_or_create_key(KEY_FILE, lambda: secrets.token_bytes(32))
ENC_KEY    = _env_enc.encode()    if _env_enc    else load_or_create_key(ENC_KEY_FILE, Fernet.generate_key)
fernet     = Fernet(ENC_KEY)

def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        return ""

# ── helpers ───────────────────────────────────────────────────────────────────
def read_json(path, default):
    try:
        return json.loads(path.read_text()) if path.exists() else default
    except Exception:
        return default

def write_json(path, data):
    path.write_text(json.dumps(data, indent=2))

def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hmac.compare_digest(h, hashlib.sha256((salt + pw).encode()).hexdigest())
    except Exception:
        return False

def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

# ── seed data ─────────────────────────────────────────────────────────────────
def seed_users():
    if not read_json(USERS_FILE, {}):
        write_json(USERS_FILE, {
            "admin":    {"password": hash_password("admin"),    "role": "admin"},
            "operator": {"password": hash_password("operator1"), "role": "operator"},
        })

def seed_devices():
    if not read_json(DEVICES_FILE, {}):
        write_json(DEVICES_FILE, {
            "core-sw-01":  {"name":"core-sw-01",  "type":"switch",       "ip":"10.0.0.1",     "port":22,  "username":"admin",    "password_enc":encrypt("switch123"),  "api_token_enc":encrypt("tok-sw-abc123"), "protocol":"SSH",   "tags":["core","production"],  "group":"core-network", "notes":"Core distribution switch",   "status":"online"},
            "core-sw-02":  {"name":"core-sw-02",  "type":"switch",       "ip":"10.0.0.2",     "port":22,  "username":"admin",    "password_enc":encrypt("switch123"),  "api_token_enc":encrypt("tok-sw-abc456"), "protocol":"SSH",   "tags":["core","production"],  "group":"core-network", "notes":"Core distribution switch 2", "status":"online"},
            "edge-fw-01":  {"name":"edge-fw-01",  "type":"firewall",     "ip":"10.0.0.254",   "port":443, "username":"admin",    "password_enc":encrypt("fw-secure!"), "api_token_enc":encrypt("tok-fw-xyz789"), "protocol":"HTTPS", "tags":["edge","production"],  "group":"perimeter",    "notes":"Perimeter firewall",          "status":"online"},
            "ap-floor2":   {"name":"ap-floor2",   "type":"access-point", "ip":"192.168.10.5", "port":22,  "username":"netadmin", "password_enc":encrypt("ap-pass"),    "api_token_enc":"",                       "protocol":"SSH",   "tags":["wireless","floor-2"], "group":"wireless",     "notes":"2nd-floor AP cluster",        "status":"warning"},
            "ap-floor3":   {"name":"ap-floor3",   "type":"access-point", "ip":"192.168.10.6", "port":22,  "username":"netadmin", "password_enc":encrypt("ap-pass"),    "api_token_enc":"",                       "protocol":"SSH",   "tags":["wireless","floor-3"], "group":"wireless",     "notes":"3rd-floor AP cluster",        "status":"online"},
            "srv-mgmt-01": {"name":"srv-mgmt-01", "type":"server",       "ip":"10.10.1.100",  "port":22,  "username":"root",     "password_enc":encrypt("srv-root"),   "api_token_enc":encrypt("tok-srv-999"),  "protocol":"SSH",   "tags":["management","infra"], "group":"servers",      "notes":"Management server",           "status":"offline"},
        })

def seed_groups():
    if not read_json(GROUPS_FILE, {}):
        write_json(GROUPS_FILE, {
            "core-network": {"name":"core-network", "desc":"Core switching layer",     "color":"blue"},
            "perimeter":    {"name":"perimeter",    "desc":"Edge and firewall devices", "color":"danger"},
            "wireless":     {"name":"wireless",     "desc":"Access points",            "color":"success"},
            "servers":      {"name":"servers",      "desc":"Server infrastructure",    "color":"warn"},
        })

def seed_scripts():
    for fname, name, desc, body in [
        ("ping_check.py", "Ping check", "ICMP reachability test",
'''# Ping check — injected: device, devices, files
import subprocess, platform

host  = device["ip"]
param = "-n" if platform.system().lower() == "windows" else "-c"
result = subprocess.run(["ping", param, "3", host],
                        capture_output=True, text=True, timeout=10)
if result.returncode == 0:
    print(f"[OK] {device['name']} ({host}) is reachable")
else:
    print(f"[FAIL] {device['name']} ({host}) did not respond")
    print(result.stdout[-500:])
'''),
        ("get_interfaces.py", "Get interface info", "Fetch interface summary via API token",
'''# Interface info — uses api_token for Bearer auth
import json, requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

name  = device["name"]
ip    = device["ip"]
token = device["api_token"]

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type":  "application/json",
}

# --- Real API call ---
# r = requests.get(f"https://{ip}/api/v1/interfaces",
#     headers=headers, verify=False, timeout=10)
# print(json.dumps(r.json(), indent=2))

# --- Simulated ---
data = {
    "device": name,
    "token_set": bool(token),
    "interfaces": [
        {"name": "GigabitEthernet0/0", "status": "up",   "ip": f"{ip}/24"},
        {"name": "GigabitEthernet0/1", "status": "down", "ip": "unassigned"},
    ]
}
print(json.dumps(data, indent=2))
'''),
        ("backup_config.py", "Backup config", "Pull and save running config — saves to backups/ for the Backups viewer",
'''# Config backup — saves to backups/ folder, viewable in the Backups tab
import datetime, os

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
name      = device["name"]
filename  = f"{name}_backup_{timestamp}.cfg"
out_dir   = "backups"
os.makedirs(out_dir, exist_ok=True)

# --- Real Netmiko call (uncomment) ---
# from netmiko import ConnectHandler
# conn = ConnectHandler(device_type="cisco_ios", host=device["ip"],
#     username=device["username"], password=device["password"], port=device["port"])
# config = conn.send_command("show running-config")
# conn.disconnect()

# --- Simulated config ---
config = f"""! Backup of {name} — {timestamp}
! Host: {device["ip"]}  Protocol: {device["protocol"]}
hostname {name}
interface GigabitEthernet0/0
  ip address {device["ip"]} 255.255.255.0
  no shutdown
line vty 0 4
  login local
  transport input ssh
end"""

path = os.path.join(out_dir, filename)
with open(path, "w") as f:
    f.write(config)

print(f"[OK] Config saved to {path}")
print(f"[INFO] View it in the Backups tab")
'''),
        ("run_commands.py", "Run commands from file", "Send each line of an uploaded command file to the device",
'''# Reads commands from an uploaded text file and runs each one
# Upload your command file in the Files tab first

name = device["name"]
ip   = device["ip"]

# Read commands from uploaded file
command_file = "commands.txt"   # change to your uploaded filename
if not files.exists(command_file):
    print(f"[WARN] {command_file} not found — upload it in the Files tab")
else:
    commands = files.lines(command_file)
    print(f"[{name}] Loaded {len(commands)} commands from {command_file}")
    for cmd in commands:
        print(f"[{name}] > {cmd}")
        # Real execution:
        # output = conn.send_command(cmd)
        # print(output)
        print(f"[{name}]   (simulated OK)")
'''),
    ]:
        p = SCRIPTS / fname
        if not p.exists():
            p.write_text(body)
            meta_path = DATA / "scripts_meta.json"
            meta = read_json(meta_path, {})
            meta[fname] = {"filename": fname, "name": name, "desc": desc, "created": datetime.now().isoformat()}
            write_json(meta_path, meta)

seed_users()
seed_devices()
seed_groups()
seed_scripts()

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_BYTES

# Security hardening — active in production (when FLASK_ENV=production)
is_production = os.environ.get("FLASK_ENV") == "production"
if is_production:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
    )

# ── SocketIO ──────────────────────────────────────────────────────────────────
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent", manage_session=False)
else:
    socketio = None

# ── rate limiting ─────────────────────────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per minute"],
        storage_uri="memory://",
    )
    RATE_LIMITING = True
except ImportError:
    # flask-limiter not installed — rate limiting disabled, log a warning
    import logging
    logging.warning("flask-limiter not installed — rate limiting disabled. Run: pip install flask-limiter")
    RATE_LIMITING = False

def rate_limit(limit_string):
    """Decorator that applies rate limiting if available, otherwise no-op."""
    def decorator(f):
        if RATE_LIMITING:
            return limiter.limit(limit_string)(f)
        return f
    return decorator

# ── decorators ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        users = read_json(USERS_FILE, {})
        if users.get(session["username"], {}).get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper

# ── frontend ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")

# ── auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
@rate_limit("10 per minute")
def login():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    users    = read_json(USERS_FILE, {})
    user     = users.get(username)
    if not user or not verify_password(password, user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    # check if TOTP is enabled for this user
    if user.get("totp_enabled") and TOTP_AVAILABLE:
        # store pending auth — not a full session yet
        session["pending_mfa_user"] = username
        return jsonify({"mfa_required": True})
    # no MFA — grant full session
    session.permanent  = True
    session["username"] = username
    session["role"]     = user["role"]
    return jsonify({"username": username, "role": user["role"]})

@app.route("/api/login/mfa", methods=["POST"])
@rate_limit("10 per minute")
def login_mfa():
    username = session.get("pending_mfa_user")
    if not username:
        return jsonify({"error": "No pending MFA session"}), 400
    code  = (request.json or {}).get("code", "").strip().replace(" ", "")
    users = read_json(USERS_FILE, {})
    user  = users.get(username)
    if not user or not user.get("totp_secret"):
        return jsonify({"error": "MFA not configured"}), 400
    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid code — check your authenticator app"}), 401
    session.pop("pending_mfa_user", None)
    session.permanent  = True
    session["username"] = username
    session["role"]     = user["role"]
    return jsonify({"username": username, "role": user["role"]})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def me():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"username": session["username"], "role": session["role"]})

# ── TOTP management ───────────────────────────────────────────────────────────
@app.route("/api/users/<username>/totp/enroll", methods=["POST"])
@admin_required
def totp_enroll(username):
    if not TOTP_AVAILABLE:
        return jsonify({"error": "pyotp not installed"}), 501
    users = read_json(USERS_FILE, {})
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    secret = pyotp.random_base32()
    uri    = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="Network Wizard"
    )
    # generate QR code as base64 PNG
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    # store secret but don't enable until confirmed
    users[username]["totp_secret"]  = secret
    users[username]["totp_enabled"] = False
    write_json(USERS_FILE, users)
    return jsonify({"qr": qr_b64, "secret": secret, "uri": uri})

@app.route("/api/users/<username>/totp/confirm", methods=["POST"])
@login_required
def totp_confirm(username):
    if not TOTP_AVAILABLE:
        return jsonify({"error": "pyotp not installed"}), 501
    # only admin or the user themselves can confirm
    if session.get("username") != username and read_json(USERS_FILE, {}).get(session.get("username"), {}).get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    code  = (request.json or {}).get("code", "").strip().replace(" ", "")
    users = read_json(USERS_FILE, {})
    if username not in users or not users[username].get("totp_secret"):
        return jsonify({"error": "No pending enrollment"}), 400
    totp = pyotp.TOTP(users[username]["totp_secret"])
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid code — try again"}), 400
    users[username]["totp_enabled"] = True
    write_json(USERS_FILE, users)
    return jsonify({"ok": True})

@app.route("/api/users/<username>/totp/disable", methods=["POST"])
@admin_required
def totp_disable(username):
    users = read_json(USERS_FILE, {})
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    users[username]["totp_enabled"] = False
    users[username].pop("totp_secret", None)
    write_json(USERS_FILE, users)
    return jsonify({"ok": True})

# ── SSH terminal (SocketIO) ───────────────────────────────────────────────────
ssh_sessions = {}   # { session_id: { 'client': ..., 'channel': ... } }

def ssh_auth_required(f):
    """SocketIO equivalent of login_required."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            emit("ssh_error", {"message": "Not authenticated"})
            disconnect()
            return
        return f(*args, **kwargs)
    return wrapper

if SOCKETIO_AVAILABLE and PARAMIKO_AVAILABLE:
    @socketio.on("ssh_connect")
    def handle_ssh_connect(data):
        if "username" not in session:
            emit("ssh_error", {"message": "Not authenticated"})
            return
        device_name = data.get("device", "").strip()
        devices     = read_json(DEVICES_FILE, {})
        device      = devices.get(device_name)
        if not device:
            emit("ssh_error", {"message": f"Device '{device_name}' not found"})
            return
        if device.get("protocol", "SSH").upper() not in ("SSH", "TELNET"):
            emit("ssh_error", {"message": f"Device uses {device.get('protocol')} — only SSH is supported for the live terminal"})
            return
        password = decrypt(device.get("password_enc", ""))
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname = device["ip"],
                port     = int(device.get("port", 22)),
                username = device.get("username", ""),
                password = password,
                timeout  = 10,
                allow_agent     = False,
                look_for_keys   = False,
            )
            cols, rows = int(data.get("cols", 220)), int(data.get("rows", 50))
            channel = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
            channel.setblocking(False)
            sid = request.sid
            ssh_sessions[sid] = {"client": client, "channel": channel, "device": device_name}
            emit("ssh_connected", {"device": device_name})
            # start background reader thread
            def read_output():
                import gevent
                while True:
                    gevent.sleep(0.01)
                    try:
                        if channel.recv_ready():
                            data = channel.recv(4096).decode("utf-8", errors="replace")
                            socketio.emit("ssh_output", {"data": data}, to=sid)
                        if channel.exit_status_ready() or channel.closed:
                            socketio.emit("ssh_disconnected", {"reason": "Connection closed"}, to=sid)
                            break
                    except Exception:
                        break
                ssh_sessions.pop(sid, None)
            socketio.start_background_task(read_output)
        except paramiko.AuthenticationException:
            emit("ssh_error", {"message": "Authentication failed — check credentials"})
        except Exception as e:
            emit("ssh_error", {"message": str(e)})

    @socketio.on("ssh_input")
    def handle_ssh_input(data):
        if "username" not in session:
            return
        sid     = request.sid
        sess    = ssh_sessions.get(sid)
        if sess:
            try:
                sess["channel"].send(data.get("data", ""))
            except Exception:
                pass

    @socketio.on("ssh_resize")
    def handle_ssh_resize(data):
        sid  = request.sid
        sess = ssh_sessions.get(sid)
        if sess:
            try:
                sess["channel"].resize_pty(
                    width  = int(data.get("cols", 220)),
                    height = int(data.get("rows", 50))
                )
            except Exception:
                pass

    @socketio.on("ssh_disconnect_request")
    def handle_ssh_disconnect():
        sid  = request.sid
        sess = ssh_sessions.pop(sid, None)
        if sess:
            try:
                sess["channel"].close()
                sess["client"].close()
            except Exception:
                pass
        emit("ssh_disconnected", {"reason": "Disconnected by user"})

    @socketio.on("disconnect")
    def handle_ws_disconnect():
        sid  = request.sid
        sess = ssh_sessions.pop(sid, None)
        if sess:
            try:
                sess["channel"].close()
                sess["client"].close()
            except Exception:
                pass


def safe_device(d):
    out = {k: v for k, v in d.items() if k not in ("password_enc", "api_token_enc")}
    out["has_password"]  = bool(d.get("password_enc"))
    out["has_api_token"] = bool(d.get("api_token_enc"))
    return out

@app.route("/api/devices", methods=["GET"])
@login_required
def get_devices():
    devices = read_json(DEVICES_FILE, {})
    return jsonify({k: safe_device(v) for k, v in devices.items()})

@app.route("/api/devices", methods=["POST"])
@login_required
def create_device():
    data = request.json or {}
    name = data.get("name", "").strip().lower().replace(" ", "-")
    if not name or not data.get("ip"):
        return jsonify({"error": "name and ip are required"}), 400
    devices  = read_json(DEVICES_FILE, {})
    existing = devices.get(name, {})
    pw    = data.get("password", "")
    token = data.get("api_token", "")

    # build dynamic UDF fields (up to MAX_UDF_FIELDS)
    udf_config = read_json(UDF_CONFIG_FILE, {})
    num_udfs   = max(5, len(udf_config.get("fields", [])))
    udfs = {}
    for i in range(1, MAX_UDF_FIELDS + 1):
        key = f"udf{i}"
        udfs[key] = data.get(key, existing.get(key, ""))

    entry = {
        "name":          name,
        "type":          data.get("type", "other"),
        "ip":            data.get("ip", ""),
        "port":          int(data.get("port", 22)),
        "username":      data.get("username", ""),
        "password_enc":  encrypt(pw)    if pw    else existing.get("password_enc", ""),
        "api_token_enc": encrypt(token) if token else existing.get("api_token_enc", ""),
        "protocol":      data.get("protocol", "SSH"),
        "tags":          data.get("tags", []),
        "group":         data.get("group", ""),
        "notes":         data.get("notes", ""),
        "notes_log":     existing.get("notes_log", []),
        "status":        data.get("status", existing.get("status", "online")),
        "created":       existing.get("created", datetime.now().isoformat()),
        "updated":       datetime.now().isoformat(),
        **udfs,
    }
    # append manual note if provided
    manual_note = data.get("manual_note", "").strip()
    if manual_note:
        entry["notes_log"].append({
            "ts":      datetime.now().isoformat(),
            "user":    session.get("username", "system"),
            "type":    "note",
            "message": manual_note,
        })
    old = data.get("_original_name")
    if old and old != name and old in devices:
        del devices[old]
    devices[name] = entry
    write_json(DEVICES_FILE, devices)
    return jsonify(safe_device(entry))

@app.route("/api/devices/<name>/note", methods=["POST"])
@login_required
def add_device_note(name):
    """Add a manual timestamped note to a device's activity log."""
    devices = read_json(DEVICES_FILE, {})
    if name not in devices:
        return jsonify({"error": "Not found"}), 404
    message = (request.json or {}).get("message", "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400
    note = {
        "ts":      datetime.now().isoformat(),
        "user":    session.get("username", "system"),
        "type":    "note",
        "message": message,
    }
    devices[name].setdefault("notes_log", []).append(note)
    write_json(DEVICES_FILE, devices)
    return jsonify(note)

@app.route("/api/devices/bulk", methods=["POST"])
@login_required
def bulk_device_action():
    """Perform a bulk action on multiple devices."""
    data    = request.json or {}
    action  = data.get("action")
    names   = data.get("devices", [])
    if not names:
        return jsonify({"error": "No devices specified"}), 400
    devices = read_json(DEVICES_FILE, {})

    if action == "delete":
        for name in names:
            devices.pop(name, None)
        write_json(DEVICES_FILE, devices)
        return jsonify({"ok": True, "count": len(names)})

    elif action == "assign_group":
        group = data.get("group", "")
        for name in names:
            if name in devices:
                devices[name]["group"] = group
        write_json(DEVICES_FILE, devices)
        return jsonify({"ok": True, "count": len(names)})

    elif action == "assign_tag":
        tag = data.get("tag", "").strip()
        if not tag:
            return jsonify({"error": "tag is required"}), 400
        for name in names:
            if name in devices:
                tags = devices[name].get("tags", [])
                if tag not in tags:
                    tags.append(tag)
                devices[name]["tags"] = tags
        write_json(DEVICES_FILE, devices)
        return jsonify({"ok": True, "count": len(names)})

    elif action == "check":
        results = {}
        def check_one(name):
            d = devices.get(name)
            if not d:
                results[name] = "not_found"
                return
            try:
                sock = socket.create_connection((d["ip"], int(d["port"])), timeout=3)
                sock.close()
                status = "online"
            except:
                status = "offline"
            d["status"] = status
            results[name] = status
            # log to notes_log
            d.setdefault("notes_log", []).append({
                "ts": datetime.now().isoformat(),
                "user": "system",
                "type": "check",
                "message": f"Reachability check: {status}",
            })
        threads = [threading.Thread(target=check_one, args=(n,)) for n in names]
        for t in threads: t.start()
        for t in threads: t.join()
        write_json(DEVICES_FILE, devices)
        return jsonify(results)

    return jsonify({"error": f"Unknown action: {action}"}), 400
    devices = read_json(DEVICES_FILE, {})
    if name not in devices:
        return jsonify({"error": "Not found"}), 404
    del devices[name]
    write_json(DEVICES_FILE, devices)
    return jsonify({"ok": True})

@app.route("/api/devices/<name>/status", methods=["PATCH"])
@login_required
def patch_status(name):
    devices = read_json(DEVICES_FILE, {})
    if name not in devices:
        return jsonify({"error": "Not found"}), 404
    devices[name]["status"] = (request.json or {}).get("status", "online")
    write_json(DEVICES_FILE, devices)
    return jsonify(safe_device(devices[name]))

# ── UDF configuration ─────────────────────────────────────────────────────────
@app.route("/api/udf-config", methods=["GET"])
@login_required
def get_udf_config():
    config = read_json(UDF_CONFIG_FILE, {})
    # default 5 fields if not configured
    if "fields" not in config:
        config["fields"] = [
            {"key": f"udf{i}", "label": f"User Defined {i}", "enabled": i <= 5}
            for i in range(1, MAX_UDF_FIELDS + 1)
        ]
    return jsonify(config)

@app.route("/api/udf-config", methods=["POST"])
@login_required
@admin_required
def save_udf_config():
    data   = request.json or {}
    fields = data.get("fields", [])
    # validate
    if len(fields) > MAX_UDF_FIELDS:
        return jsonify({"error": f"Maximum {MAX_UDF_FIELDS} UDF fields allowed"}), 400
    config = {"fields": fields}
    write_json(UDF_CONFIG_FILE, config)
    return jsonify(config)

# ── groups ────────────────────────────────────────────────────────────────────
@app.route("/api/groups", methods=["GET"])
@login_required
def get_groups():
    groups  = read_json(GROUPS_FILE, {})
    devices = read_json(DEVICES_FILE, {})
    for g in groups.values():
        g["count"] = sum(1 for d in devices.values() if d.get("group") == g["name"])
    return jsonify(groups)

@app.route("/api/groups", methods=["POST"])
@login_required
def create_group():
    data = request.json or {}
    name = data.get("name", "").strip().lower().replace(" ", "-")
    if not name:
        return jsonify({"error": "name is required"}), 400
    groups = read_json(GROUPS_FILE, {})
    groups[name] = {"name": name, "desc": data.get("desc", ""), "color": data.get("color", "blue"), "created": datetime.now().isoformat()}
    write_json(GROUPS_FILE, groups)
    return jsonify(groups[name])

@app.route("/api/groups/<name>", methods=["PUT"])
@login_required
def update_group(name):
    groups = read_json(GROUPS_FILE, {})
    if name not in groups:
        return jsonify({"error": "Not found"}), 404
    data     = request.json or {}
    new_name = data.get("name", name).strip().lower().replace(" ", "-")
    new_desc  = data.get("desc",  groups[name].get("desc",  ""))
    new_color = data.get("color", groups[name].get("color", "blue"))
    if not new_name:
        return jsonify({"error": "name is required"}), 400
    # if name changed, rename key and update all devices
    if new_name != name:
        if new_name in groups:
            return jsonify({"error": f"Group '{new_name}' already exists"}), 409
        groups[new_name] = {**groups[name], "name": new_name, "desc": new_desc, "color": new_color}
        del groups[name]
        devices = read_json(DEVICES_FILE, {})
        for d in devices.values():
            if d.get("group") == name:
                d["group"] = new_name
        write_json(DEVICES_FILE, devices)
    else:
        groups[name]["desc"]  = new_desc
        groups[name]["color"] = new_color
    write_json(GROUPS_FILE, groups)
    return jsonify(groups[new_name])

@app.route("/api/groups/<name>", methods=["DELETE"])
@login_required
def delete_group(name):
    groups = read_json(GROUPS_FILE, {})
    if name not in groups:
        return jsonify({"error": "Not found"}), 404
    del groups[name]
    write_json(GROUPS_FILE, groups)
    devices = read_json(DEVICES_FILE, {})
    for d in devices.values():
        if d.get("group") == name:
            d["group"] = ""
    write_json(DEVICES_FILE, devices)
    return jsonify({"ok": True})

# ── files ─────────────────────────────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
@login_required
def list_files():
    result = []
    for f in sorted(UPLOADS.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file() and not f.name.startswith('.'):
            result.append({
                "name":     f.name,
                "size":     f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    return jsonify(result)

@app.route("/api/files", methods=["POST"])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({"error": "No filename"}), 400
    if not allowed_file(f.filename):
        return jsonify({"error": f"File type not allowed. Permitted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"}), 400
    filename = secure_filename(f.filename)
    dest = UPLOADS / filename
    f.save(str(dest))
    return jsonify({"name": filename, "size": dest.stat().st_size})

@app.route("/api/files/<filename>", methods=["GET"])
@login_required
def get_file_content(filename):
    p = UPLOADS / secure_filename(filename)
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    try:
        return jsonify({"filename": filename, "content": p.read_text(errors='replace')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/<filename>", methods=["PUT"])
@login_required
def save_file_content(filename):
    p    = UPLOADS / secure_filename(filename)
    data = request.json or {}
    content = data.get("content", "")
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    # validate JSON files
    if filename.endswith('.json'):
        try:
            import json as _json
            _json.loads(content)
        except Exception as e:
            return jsonify({"error": f"Invalid JSON: {e}"}), 400
    p.write_text(content)
    return jsonify({"ok": True, "filename": filename, "size": len(content)})

@app.route("/api/files/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    p = UPLOADS / secure_filename(filename)
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    p.unlink()
    return jsonify({"ok": True})

@app.route("/api/files/<filename>/download")
@login_required
def download_file(filename):
    return send_from_directory(str(UPLOADS), secure_filename(filename), as_attachment=True)

# ── resolve targets ───────────────────────────────────────────────────────────
def resolve_targets(target_type, target_value, explicit_devices):
    all_devices = read_json(DEVICES_FILE, {})
    if target_type == "group":
        return [k for k, d in all_devices.items() if d.get("group") == target_value]
    elif target_type == "tag":
        return [k for k, d in all_devices.items() if target_value in (d.get("tags") or [])]
    else:
        return explicit_devices or []

# ── scripts ───────────────────────────────────────────────────────────────────
@app.route("/api/scripts", methods=["GET"])
@login_required
def get_scripts():
    meta   = read_json(DATA / "scripts_meta.json", {})
    result = []
    for fname, m in meta.items():
        p = SCRIPTS / fname
        result.append({**m, "body": p.read_text() if p.exists() else ""})
    return jsonify(result)

@app.route("/api/scripts", methods=["POST"])
@login_required
def create_script():
    data  = request.json or {}
    name  = data.get("name", "").strip()
    body  = data.get("body", "").strip()
    if not name or not body:
        return jsonify({"error": "name and body are required"}), 400
    fname = data.get("filename") or (name.lower().replace(" ", "_") + ".py")
    meta  = read_json(DATA / "scripts_meta.json", {})
    entry = {
        "filename": fname,
        "name":     name,
        "desc":     data.get("desc", ""),
        "timeout":  int(data.get("timeout", meta.get(fname, {}).get("timeout", 30))),
        "tags":     [t.strip() for t in data.get("tags", "").split(",") if t.strip()] if isinstance(data.get("tags"), str) else data.get("tags", meta.get(fname, {}).get("tags", [])),
        "created":  meta.get(fname, {}).get("created", datetime.now().isoformat()),
        "updated":  datetime.now().isoformat(),
    }
    (SCRIPTS / fname).write_text(body)
    meta[fname] = entry
    write_json(DATA / "scripts_meta.json", meta)
    return jsonify({**entry, "body": body})

@app.route("/api/scripts/<path:fname>/inputs")
@login_required
def get_script_inputs(fname):
    """Parse and return the input declarations from a script."""
    p = SCRIPTS / fname
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    return jsonify(parse_script_inputs(p.read_text()))

@app.route("/api/scripts/export")
@login_required
def export_scripts():
    """Export all scripts as a zip file."""
    import zipfile, io
    meta = read_json(DATA / "scripts_meta.json", {})
    buf  = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # write each script file
        for fname, m in meta.items():
            p = SCRIPTS / fname
            if p.exists():
                zf.write(str(p), fname)
        # write metadata
        zf.writestr("_scripts_meta.json", json.dumps(meta, indent=2))
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/zip",
        headers={"Content-Disposition": "attachment; filename=network-wizard-scripts.zip"}
    )

@app.route("/api/scripts/import", methods=["POST"])
@login_required
def import_scripts():
    """Import scripts from a zip file."""
    import zipfile, io
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files['file']
    if not f.filename or not f.filename.endswith('.zip'):
        return jsonify({"error": "File must be a .zip"}), 400
    mode = request.args.get("mode", "merge")  # merge or replace
    try:
        zf = zipfile.ZipFile(io.BytesIO(f.read()))
    except Exception:
        return jsonify({"error": "Invalid zip file"}), 400

    meta = read_json(DATA / "scripts_meta.json", {}) if mode == "merge" else {}
    imported, skipped = 0, 0
    imported_meta = {}

    # read embedded metadata if present
    if "_scripts_meta.json" in zf.namelist():
        try:
            imported_meta = json.loads(zf.read("_scripts_meta.json"))
        except Exception:
            pass

    for name in zf.namelist():
        if name.startswith('_') or name.startswith('/') or '..' in name:
            continue
        ext = Path(name).suffix.lower()
        if ext not in ('.py', '.sh'):
            skipped += 1
            continue
        try:
            body    = zf.read(name).decode('utf-8')
            fname   = secure_filename(name)
            (SCRIPTS / fname).write_text(body)
            # use embedded meta if available, else generate
            m = imported_meta.get(name) or imported_meta.get(fname) or {}
            meta[fname] = {
                "filename": fname,
                "name":     m.get("name") or fname.replace('_', ' ').replace('.py','').replace('.sh','').title(),
                "desc":     m.get("desc", ""),
                "created":  meta.get(fname, {}).get("created", datetime.now().isoformat()),
                "updated":  datetime.now().isoformat(),
            }
            imported += 1
        except Exception:
            skipped += 1

    write_json(DATA / "scripts_meta.json", meta)
    return jsonify({"imported": imported, "skipped": skipped, "total": len(meta), "mode": mode})

@app.route("/api/scripts/<path:fname>", methods=["DELETE"])
@login_required
def delete_script(fname):
    meta = read_json(DATA / "scripts_meta.json", {})
    if fname not in meta:
        return jsonify({"error": "Not found"}), 404
    del meta[fname]
    write_json(DATA / "scripts_meta.json", meta)
    p = SCRIPTS / fname
    if p.exists():
        p.unlink()
    return jsonify({"ok": True})

def parse_script_inputs(script_body):
    """
    Parse input declarations from script comments.

    # INPUTS:
    # key: type
    # key: type | label
    # key: type | label | default

    Types: text, number, password, checkbox, select[opt1,opt2]
    """
    import re
    inputs = []
    in_block = False
    for line in script_body.splitlines():
        stripped = line.strip()
        # detect INPUTS: header — allow anything after the colon
        if re.match(r'^#\s*INPUTS\s*:', stripped, re.IGNORECASE):
            in_block = True
            continue
        if in_block:
            if not stripped.startswith('#'):
                break  # non-comment line ends the block
            content = stripped.lstrip('#').strip()
            if not content:
                continue
            # split on colon to get key and the rest
            if ':' not in content:
                continue
            key_part, _, rest = content.partition(':')
            key = key_part.strip()
            if not key or not re.match(r'^\w+$', key):
                continue
            # split rest on | to get type, optional label, optional default
            parts = [p.strip() for p in rest.split('|')]
            raw_type = parts[0].strip() if parts else 'text'
            label    = parts[1].strip() if len(parts) > 1 else key.replace('_', ' ').title()
            default  = parts[2].strip() if len(parts) > 2 else ''
            if not label:
                label = key.replace('_', ' ').title()
            # detect select type
            sel_match = re.match(r'^select\[(.+)\]$', raw_type, re.IGNORECASE)
            if sel_match:
                options = [o.strip() for o in sel_match.group(1).split(',')]
                inputs.append({"key": key, "type": "select", "label": label,
                               "default": default or options[0], "options": options})
            else:
                type_map = {"text":"text","number":"number","password":"password",
                            "checkbox":"checkbox","bool":"checkbox","boolean":"checkbox"}
                inp_type = type_map.get(raw_type.lower(), "text")
                inputs.append({"key": key, "type": inp_type, "label": label, "default": default})
    return inputs

# ── shared script execution helper ───────────────────────────────────────────
def _execute_script_on_device(device_ctx, devices_for_script, env_vars_for_script,
                               script_path, script_body, script_inputs,
                               selected_file, dry_run=False, timeout=30):
    """Execute a single script against a single device. Returns dict with ok, output."""
    ext = Path(script_path.name).suffix.lower()

    if dry_run:
        inputs_str = json.dumps(script_inputs, indent=2) if script_inputs else "none"
        return {
            "ok": True,
            "output": (
                f"[DRY RUN] Would execute: {script_path.name}\n"
                f"  Device:   {device_ctx['name']} ({device_ctx['ip']})\n"
                f"  Protocol: {device_ctx['protocol']}\n"
                f"  File:     {selected_file or 'none'}\n"
                f"  Inputs:   {inputs_str}"
            )
        }

    files_helper = f"""
import os as _os

class _Files:
    _dir = {json.dumps(str(UPLOADS))}
    def path(self, name):
        p = _os.path.join(self._dir, name)
        if not _os.path.exists(p):
            raise FileNotFoundError(f"Uploaded file '{{name}}' not found.")
        return p
    def read(self, name):
        with open(self.path(name), 'r') as f:
            return f.read()
    def lines(self, name):
        return [l.rstrip('\\n') for l in self.read(name).splitlines() if l.strip()]
    def exists(self, name):
        return _os.path.exists(_os.path.join(self._dir, name))

files = _Files()
"""
    selected_file_injection = ""
    if selected_file and (UPLOADS / selected_file).exists():
        selected_file_injection = f"""
selected_filename = {json.dumps(selected_file)}
selected_file     = files.path({json.dumps(selected_file)})
"""

    sandbox_uid, sandbox_gid = get_sandbox_uid_gid()
    def drop_privileges():
        if sandbox_uid is not None:
            os.setgid(sandbox_gid)
            os.setuid(sandbox_uid)

    try:
        if ext == '.sh':
            env = os.environ.copy()
            env.update({
                'DEVICE_NAME':      device_ctx['name'],
                'DEVICE_IP':        device_ctx['ip'],
                'DEVICE_PORT':      str(device_ctx['port']),
                'DEVICE_USERNAME':  device_ctx['username'],
                'DEVICE_PASSWORD':  device_ctx['password'],
                'DEVICE_TOKEN':     device_ctx['api_token'],
                'DEVICE_PROTOCOL':  device_ctx['protocol'],
                'DEVICE_GROUP':     device_ctx.get('group', ''),
                'DEVICE_UDF1':      device_ctx.get('udf1', ''),
                'DEVICE_UDF2':      device_ctx.get('udf2', ''),
                'DEVICE_UDF3':      device_ctx.get('udf3', ''),
                'DEVICE_UDF4':      device_ctx.get('udf4', ''),
                'DEVICE_UDF5':      device_ctx.get('udf5', ''),
                'FILES_DIR':        str(UPLOADS),
                'SELECTED_FILE':    str(UPLOADS / selected_file) if selected_file else '',
                'SELECTED_FILENAME': selected_file,
            })
            for k, v in env_vars_for_script.items():
                env[f'NW_{k}'] = v
            for k, v in script_inputs.items():
                env[f'NW_INPUT_{k.upper()}'] = str(v)
            proc = subprocess.run(
                ['bash', str(script_path)],
                capture_output=True, text=True,
                timeout=timeout, cwd=str(BASE), env=env,
                preexec_fn=drop_privileges,
            )
        else:
            wrapper = f"""import sys, json
device        = {json.dumps(device_ctx)}
devices       = {json.dumps(devices_for_script)}
env_vars      = {json.dumps(env_vars_for_script)}
script_inputs = {repr(script_inputs)}
{files_helper}
{selected_file_injection}
# ── user script ──────────────────────────────────────────────────────
{script_body}
"""
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
                tmp.write(wrapper)
                tmp_path = tmp.name
                os.chmod(tmp_path, 0o644)
            proc = subprocess.run(
                [sys.executable, tmp_path],
                capture_output=True, text=True,
                timeout=timeout, cwd=str(BASE),
                preexec_fn=drop_privileges,
            )
            os.unlink(tmp_path)

        return {
            "ok":     proc.returncode == 0,
            "output": (proc.stdout + proc.stderr).strip() or "(no output)"
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"Timed out after {timeout} seconds."}
    except Exception as e:
        return {"ok": False, "output": str(e)}

# ── streaming run (Server-Sent Events) ────────────────────────────────────────
@app.route("/api/run/stream", methods=["GET"])
@login_required
def run_script_stream():
    """Streaming version of /api/run — sends SSE events as each device executes."""
    filename      = request.args.get("filename")
    target_type   = request.args.get("target_type", "devices")
    target_value  = request.args.get("target_value", "")
    explicit      = json.loads(request.args.get("devices", "[]"))
    selected_file = os.path.basename(request.args.get("selected_file", ""))
    script_inputs = json.loads(request.args.get("script_inputs", "{}"))
    dry_run       = request.args.get("dry_run", "false") == "true"
    timeout_val   = int(request.args.get("timeout", "30"))

    def generate():
        def sse(event, data):
            return f"event: {event}\ndata: {json.dumps(data)}\n\n"

        if not filename:
            yield sse("error", {"message": "filename is required"}); return
        script_path = SCRIPTS / filename
        if not script_path.exists():
            yield sse("error", {"message": "Script not found"}); return

        device_names = resolve_targets(target_type, target_value, explicit)
        if not device_names:
            yield sse("error", {"message": "No devices matched"}); return

        script_body = script_path.read_text()
        all_devices = read_json(DEVICES_FILE, {})
        all_env     = read_json(ENV_VARS_FILE, {})
        env_vars_for_script = {k: v["value"] for k, v in all_env.items()}
        meta    = read_json(DATA / "scripts_meta.json", {})
        timeout = max(5, min(int(request.args.get("timeout", meta.get(filename, {}).get("timeout", 30))), 3600))

        # coerce inputs
        si = dict(script_inputs)
        parsed_inputs = parse_script_inputs(script_body)
        for inp in parsed_inputs:
            k = inp["key"]
            if k not in si: si[k] = inp["default"]
            if inp["type"] == "number":
                try: si[k] = float(si[k]) if '.' in str(si[k]) else int(si[k])
                except: pass
            elif inp["type"] == "checkbox":
                si[k] = si[k] in (True, "true", "True", "1", "on", 1)

        devices_for_script = {}
        for k, v in all_devices.items():
            d = dict(v)
            d["password"]  = decrypt(d.pop("password_enc",  ""))
            d["api_token"] = decrypt(d.pop("api_token_enc", ""))
            devices_for_script[k] = d

        total = len(device_names)
        yield sse("start", {"total": total, "filename": filename, "dry_run": dry_run})

        hist = read_json(HISTORY_FILE, [])
        all_devices_fresh = read_json(DEVICES_FILE, {})
        ok_count, err_count = 0, 0

        for idx, dev_name in enumerate(device_names):
            yield sse("device_start", {"device": dev_name, "index": idx, "total": total})

            if dev_name not in all_devices:
                yield sse("device_done", {"device": dev_name, "ok": False,
                    "output": f"Device '{dev_name}' not found.", "index": idx, "total": total,
                    "ok_count": ok_count, "err_count": err_count + 1})
                err_count += 1
                continue

            result = _execute_script_on_device(
                devices_for_script[dev_name], devices_for_script, env_vars_for_script,
                script_path, script_body, si, selected_file, dry_run, timeout
            )

            if result["ok"]: ok_count += 1
            else: err_count += 1

            yield sse("device_done", {
                "device":    dev_name,
                "ok":        result["ok"],
                "output":    result["output"],
                "index":     idx,
                "total":     total,
                "ok_count":  ok_count,
                "err_count": err_count,
            })

            if not dry_run:
                event_name = "script_run_complete" if result["ok"] else "script_run_failed"
                fire_webhooks(event_name, {
                    "script": filename, "device": dev_name,
                    "ok": result["ok"], "user": session.get("username"),
                    "ts": datetime.now().isoformat(),
                })
                hist.append({
                    "script": filename, "device": dev_name, "ok": result["ok"],
                    "ts": datetime.now().isoformat(), "user": session.get("username"),
                    "target_type": target_type, "target_value": target_value,
                    "selected_file": selected_file, "script_inputs": si,
                })
                if dev_name in all_devices_fresh:
                    all_devices_fresh[dev_name].setdefault("notes_log", []).append({
                        "ts": datetime.now().isoformat(), "user": session.get("username", "system"),
                        "type": "script_run",
                        "message": f"Script '{filename}' ran — {'✓ success' if result['ok'] else '✗ failed'}",
                    })

        if not dry_run:
            write_json(HISTORY_FILE, hist[-500:])
            write_json(DEVICES_FILE, all_devices_fresh)

        yield sse("complete", {
            "total": total, "ok_count": ok_count, "err_count": err_count,
            "dry_run": dry_run,
        })

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        }
    )

# ── run ───────────────────────────────────────────────────────────────────────
@app.route("/api/run", methods=["POST"])
@login_required
def run_script():
    data          = request.json or {}
    filename      = data.get("filename")
    target_type   = data.get("target_type", "devices")
    target_value  = data.get("target_value", "")
    explicit      = data.get("devices", [])
    selected_file = os.path.basename(data.get("selected_file", ""))
    script_inputs = data.get("script_inputs", {})
    dry_run       = data.get("dry_run", False)

    if not filename:
        return jsonify({"error": "filename is required"}), 400
    script_path = SCRIPTS / filename
    if not script_path.exists():
        return jsonify({"error": "Script not found"}), 404

    device_names = resolve_targets(target_type, target_value, explicit)
    if not device_names:
        return jsonify({"error": "No devices matched the target selection"}), 400

    script_body = script_path.read_text()
    all_devices = read_json(DEVICES_FILE, {})
    all_env     = read_json(ENV_VARS_FILE, {})
    env_vars_for_script = {k: v["value"] for k, v in all_env.items()}

    # get script timeout — per-run override takes precedence over stored default
    meta    = read_json(DATA / "scripts_meta.json", {})
    timeout = int(data.get("timeout") or meta.get(filename, {}).get("timeout", 30))
    timeout = max(5, min(timeout, 3600))  # clamp 5s–60min

    parsed_inputs = parse_script_inputs(script_body)
    for inp in parsed_inputs:
        k = inp["key"]
        if k not in script_inputs:
            script_inputs[k] = inp["default"]
        if inp["type"] == "number":
            try: script_inputs[k] = float(script_inputs[k]) if '.' in str(script_inputs[k]) else int(script_inputs[k])
            except: pass
        elif inp["type"] == "checkbox":
            script_inputs[k] = script_inputs[k] in (True, "true", "True", "1", "on", 1)

    devices_for_script = {}
    for k, v in all_devices.items():
        d = dict(v)
        d["password"]  = decrypt(d.pop("password_enc",  ""))
        d["api_token"] = decrypt(d.pop("api_token_enc", ""))
        devices_for_script[k] = d

    results = []
    for dev_name in device_names:
        if dev_name not in all_devices:
            results.append({"device": dev_name, "ok": False, "output": f"Device '{dev_name}' not found."})
            continue
        r = _execute_script_on_device(
            devices_for_script[dev_name], devices_for_script, env_vars_for_script,
            script_path, script_body, script_inputs, selected_file, dry_run, timeout
        )
        results.append({"device": dev_name, **r})

    if not dry_run:
        hist = read_json(HISTORY_FILE, [])
        # reload devices to add notes_log entries
        all_devices_fresh = read_json(DEVICES_FILE, {})
        for r in results:
            hist.append({
                "script":        filename,
                "device":        r["device"],
                "ok":            r["ok"],
                "ts":            datetime.now().isoformat(),
                "user":          session.get("username"),
                "target_type":   target_type,
                "target_value":  target_value,
                "selected_file": selected_file,
                "script_inputs": script_inputs,
            })
            # log to device activity log
            if r["device"] in all_devices_fresh:
                all_devices_fresh[r["device"]].setdefault("notes_log", []).append({
                    "ts":      datetime.now().isoformat(),
                    "user":    session.get("username", "system"),
                    "type":    "script_run",
                    "message": f"Script '{filename}' ran — {'✓ success' if r['ok'] else '✗ failed'}",
                })
            # fire outbound webhooks
            fire_webhooks(
                "script_run_complete" if r["ok"] else "script_run_failed",
                {"script": filename, "device": r["device"], "ok": r["ok"],
                 "user": session.get("username"), "ts": datetime.now().isoformat()}
            )
        write_json(HISTORY_FILE, hist[-500:])
        write_json(DEVICES_FILE, all_devices_fresh)

    return jsonify({"results": results, "device_count": len(device_names)})

# ── playbooks ─────────────────────────────────────────────────────────────────
PLAYBOOKS_FILE = DATA / "playbooks.json"

@app.route("/api/playbooks/export")
@login_required
def export_playbooks():
    playbooks = read_json(PLAYBOOKS_FILE, {})
    return Response(
        json.dumps(playbooks, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=network-wizard-playbooks.json"}
    )

@app.route("/api/playbooks/import", methods=["POST"])
@login_required
def import_playbooks():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files['file']
    try:
        data = json.loads(f.read())
        playbooks = read_json(PLAYBOOKS_FILE, {})
        imported = 0
        for pid, pb in data.items():
            if 'name' in pb and 'steps' in pb:
                pb['id'] = pid
                pb['updated'] = datetime.now().isoformat()
                playbooks[pid] = pb
                imported += 1
        write_json(PLAYBOOKS_FILE, playbooks)
        return jsonify({"imported": imported, "total": len(playbooks)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/playbooks", methods=["GET"])
@login_required
def get_playbooks():
    return jsonify(read_json(PLAYBOOKS_FILE, {}))

@app.route("/api/playbooks", methods=["POST"])
@login_required
def save_playbook():
    data  = request.json or {}
    name  = data.get("name", "").strip()
    steps = data.get("steps", [])
    if not name:
        return jsonify({"error": "name is required"}), 400
    if not steps:
        return jsonify({"error": "at least one step is required"}), 400
    pid       = data.get("id") or f"pb_{secrets.token_hex(4)}"
    playbooks = read_json(PLAYBOOKS_FILE, {})
    playbooks[pid] = {
        "id":             pid,
        "name":           name,
        "desc":           data.get("desc", ""),
        "steps":          steps,  # [{filename, delay_secs, script_inputs, selected_file, stop_on_failure}]
        "stop_on_failure": data.get("stop_on_failure", True),
        "created":        playbooks.get(pid, {}).get("created", datetime.now().isoformat()),
        "updated":        datetime.now().isoformat(),
    }
    write_json(PLAYBOOKS_FILE, playbooks)
    return jsonify(playbooks[pid])

@app.route("/api/playbooks/<pid>", methods=["DELETE"])
@login_required
def delete_playbook(pid):
    playbooks = read_json(PLAYBOOKS_FILE, {})
    if pid not in playbooks:
        return jsonify({"error": "Not found"}), 404
    del playbooks[pid]
    write_json(PLAYBOOKS_FILE, playbooks)
    return jsonify({"ok": True})

@app.route("/api/run/playbook", methods=["POST"])
@login_required
def run_playbook():
    data         = request.json or {}
    pid          = data.get("playbook_id")
    target_type  = data.get("target_type", "devices")
    target_value = data.get("target_value", "")
    explicit     = data.get("devices", [])
    dry_run      = data.get("dry_run", False)

    playbooks = read_json(PLAYBOOKS_FILE, {})
    if not pid or pid not in playbooks:
        return jsonify({"error": "Playbook not found"}), 404

    pb           = playbooks[pid]
    device_names = resolve_targets(target_type, target_value, explicit)
    if not device_names:
        return jsonify({"error": "No devices matched"}), 400

    all_devices = read_json(DEVICES_FILE, {})
    all_env     = read_json(ENV_VARS_FILE, {})
    env_vars_for_script = {k: v["value"] for k, v in all_env.items()}

    devices_for_script = {}
    for k, v in all_devices.items():
        d = dict(v)
        d["password"]  = decrypt(d.pop("password_enc",  ""))
        d["api_token"] = decrypt(d.pop("api_token_enc", ""))
        devices_for_script[k] = d

    stop_on_failure = pb.get("stop_on_failure", True)
    step_results    = []

    for step_num, step in enumerate(pb["steps"], 1):
        import time
        fname         = step.get("filename", "")
        delay_secs    = int(step.get("delay_secs", 0))
        step_inputs   = step.get("script_inputs", {})
        step_file     = os.path.basename(step.get("selected_file", ""))
        script_path   = SCRIPTS / fname

        # optional delay before step (not on first step)
        if delay_secs and step_num > 1 and not dry_run:
            time.sleep(delay_secs)

        if not script_path.exists():
            step_results.append({
                "step": step_num, "script": fname, "delay": delay_secs,
                "results": [{"device": d, "ok": False, "output": f"Script '{fname}' not found."} for d in device_names]
            })
            if stop_on_failure:
                break
            continue

        script_body   = script_path.read_text()
        parsed_inputs = parse_script_inputs(script_body)
        merged_inputs = dict(step_inputs)
        for inp in parsed_inputs:
            k = inp["key"]
            if k not in merged_inputs:
                merged_inputs[k] = inp["default"]
            if inp["type"] == "number":
                try: merged_inputs[k] = float(merged_inputs[k]) if '.' in str(merged_inputs[k]) else int(merged_inputs[k])
                except: pass
            elif inp["type"] == "checkbox":
                merged_inputs[k] = merged_inputs[k] in (True, "true", "True", "1", "on", 1)

        device_step_results = []
        # track per-device failure for stop_on_failure
        failed_devices = set()

        for dev_name in device_names:
            if dev_name not in devices_for_script:
                device_step_results.append({"device": dev_name, "ok": False, "output": f"Device '{dev_name}' not found."})
                failed_devices.add(dev_name)
                continue
            r = _execute_script_on_device(
                devices_for_script[dev_name], devices_for_script, env_vars_for_script,
                script_path, script_body, merged_inputs, step_file, dry_run
            )
            device_step_results.append({"device": dev_name, **r})
            if not r["ok"]:
                failed_devices.add(dev_name)

        step_results.append({
            "step":    step_num,
            "script":  fname,
            "delay":   delay_secs,
            "results": device_step_results,
        })

        # if stop_on_failure, remove failed devices from subsequent steps
        if stop_on_failure and failed_devices:
            device_names = [d for d in device_names if d not in failed_devices]
            if not device_names:
                break  # all devices failed — stop entirely

    # persist history
    if not dry_run:
        hist = read_json(HISTORY_FILE, [])
        for s in step_results:
            for r in s["results"]:
                hist.append({
                    "script":   f"[{pb['name']}] {s['script']}",
                    "device":   r["device"],
                    "ok":       r["ok"],
                    "ts":       datetime.now().isoformat(),
                    "user":     session.get("username"),
                    "playbook": pb["name"],
                    "step":     s["step"],
                })
        write_json(HISTORY_FILE, hist[-500:])

    return jsonify({
        "steps":        len(step_results),
        "devices":      len(set(d for s in step_results for r in s["results"] for d in [r["device"]])),
        "step_results": step_results,
        "dry_run":      dry_run,
    })

# ── history ───────────────────────────────────────────────────────────────────
@app.route("/api/history")
@login_required
def get_history():
    hist = read_json(HISTORY_FILE, [])
    return jsonify(hist[-100:][::-1])

# ── devices.json import ──────────────────────────────────────────────────────
@app.route("/api/devices/import", methods=["POST"])
@login_required
def import_devices():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files['file']
    if not f.filename or not f.filename.endswith('.json'):
        return jsonify({"error": "File must be a .json file"}), 400
    try:
        raw = json.loads(f.read().decode('utf-8'))
    except Exception:
        return jsonify({"error": "Invalid JSON — could not parse file"}), 400

    if not isinstance(raw, dict):
        return jsonify({"error": "JSON must be an object/dictionary of devices"}), 400

    mode    = request.args.get("mode", "merge")  # merge or replace
    devices = read_json(DEVICES_FILE, {}) if mode == "merge" else {}
    imported, skipped = 0, 0

    for key, d in raw.items():
        if not isinstance(d, dict):
            skipped += 1
            continue

        name = d.get("name") or key
        name = str(name).strip().lower().replace(" ", "-")
        if not name:
            skipped += 1
            continue

        # handle both encrypted (from our own export) and plaintext (user-created)
        existing  = devices.get(name, {})
        pw_plain  = d.get("password",  "")
        tok_plain = d.get("api_token", "")
        pw_enc    = d.get("password_enc",  "")
        tok_enc   = d.get("api_token_enc", "")

        devices[name] = {
            "name":          name,
            "type":          d.get("type",     existing.get("type",     "other")),
            "ip":            d.get("ip",        existing.get("ip",       "")),
            "port":          int(d.get("port",  existing.get("port",     22))),
            "username":      d.get("username",  existing.get("username", "")),
            "password_enc":  pw_enc  if pw_enc  else (encrypt(pw_plain)  if pw_plain  else existing.get("password_enc",  "")),
            "api_token_enc": tok_enc if tok_enc else (encrypt(tok_plain) if tok_plain else existing.get("api_token_enc", "")),
            "protocol":      d.get("protocol", existing.get("protocol", "SSH")),
            "tags":          d.get("tags",     existing.get("tags",     [])),
            "group":         d.get("group",    existing.get("group",    "")),
            "notes":         d.get("notes",    existing.get("notes",    "")),
            "status":        d.get("status",   existing.get("status",   "online")),
            "udf1":          d.get("udf1",     existing.get("udf1",     "")),
            "udf2":          d.get("udf2",     existing.get("udf2",     "")),
            "udf3":          d.get("udf3",     existing.get("udf3",     "")),
            "udf4":          d.get("udf4",     existing.get("udf4",     "")),
            "udf5":          d.get("udf5",     existing.get("udf5",     "")),
            "created":       existing.get("created", datetime.now().isoformat()),
            "updated":       datetime.now().isoformat(),
        }
        imported += 1

    write_json(DEVICES_FILE, devices)
    return jsonify({
        "imported": imported,
        "skipped":  skipped,
        "total":    len(devices),
        "mode":     mode,
    })

# ── dictionary (safe — masked for UI display) ─────────────────────────────────
@app.route("/api/dictionary")
@login_required
def get_dictionary_safe():
    """Returns devices with passwords/tokens masked — safe for UI display."""
    devices = read_json(DEVICES_FILE, {})
    out = {}
    for k, v in devices.items():
        d = {key: val for key, val in v.items() if key not in ("password_enc", "api_token_enc")}
        d["password"]  = "●●●●●●●●" if v.get("password_enc")  else "not set"
        d["api_token"] = "●●●●●●●●" if v.get("api_token_enc") else "not set"
        out[k] = d
    return jsonify(out)

@app.route("/api/dictionary/export")
@login_required
def get_dictionary_export():
    """Returns devices with passwords/tokens decrypted — for download/copy only."""
    devices = read_json(DEVICES_FILE, {})
    out = {}
    for k, v in devices.items():
        d = dict(v)
        d["password"]  = decrypt(d.pop("password_enc",  ""))
        d["api_token"] = decrypt(d.pop("api_token_enc", ""))
        out[k] = d
    return jsonify(out)

# ── environment variables ─────────────────────────────────────────────────────
@app.route("/api/envvars", methods=["GET"])
@login_required
def get_env_vars():
    return jsonify(read_json(ENV_VARS_FILE, {}))

@app.route("/api/envvars", methods=["POST"])
@login_required
def save_env_var():
    data  = request.json or {}
    key   = data.get("key",   "").strip().replace(" ", "_")
    value = data.get("value", "").strip()
    desc  = data.get("desc",  "").strip()
    if not key:
        return jsonify({"error": "key is required"}), 400
    env_vars = read_json(ENV_VARS_FILE, {})
    env_vars[key] = {"key": key, "value": value, "desc": desc, "updated": datetime.now().isoformat()}
    write_json(ENV_VARS_FILE, env_vars)
    return jsonify(env_vars[key])

@app.route("/api/envvars/<key>", methods=["DELETE"])
@login_required
def delete_env_var(key):
    env_vars = read_json(ENV_VARS_FILE, {})
    if key not in env_vars:
        return jsonify({"error": "Not found"}), 404
    del env_vars[key]
    write_json(ENV_VARS_FILE, env_vars)
    return jsonify({"ok": True})

# ── device reachability check ─────────────────────────────────────────────────
@app.route("/api/devices/<name>/check", methods=["POST"])
@login_required
def check_device(name):
    devices = read_json(DEVICES_FILE, {})
    if name not in devices:
        return jsonify({"error": "Not found"}), 404
    d = devices[name]
    try:
        sock = socket.create_connection((d["ip"], int(d["port"])), timeout=3)
        sock.close()
        status = "online"
    except (socket.timeout, ConnectionRefusedError, OSError):
        status = "offline"
    d["status"] = status
    devices[name] = d
    write_json(DEVICES_FILE, devices)
    if status == "offline":
        fire_webhooks("device_offline", {"device": name, "ip": d["ip"], "port": d["port"]})
    return jsonify({"name": name, "status": status, "ip": d["ip"], "port": d["port"]})

@app.route("/api/devices/checkall", methods=["POST"])
@login_required
def check_all_devices():
    devices = read_json(DEVICES_FILE, {})
    results = {}
    def check_one(name, d):
        try:
            sock = socket.create_connection((d["ip"], int(d["port"])), timeout=3)
            sock.close()
            status = "online"
        except:
            status = "offline"
        d["status"] = status
        results[name] = status
    threads = [threading.Thread(target=check_one, args=(n, d)) for n, d in devices.items()]
    for t in threads: t.start()
    for t in threads: t.join()
    for name, d in devices.items():
        d["status"] = results.get(name, d.get("status", "offline"))
    write_json(DEVICES_FILE, devices)
    return jsonify(results)

# ── network tools ─────────────────────────────────────────────────────────────
@app.route("/api/tools/ping", methods=["POST"])
@login_required
def tool_ping():
    data   = request.json or {}
    target = data.get("target", "").strip()
    count  = min(int(data.get("count", 4)), 20)
    if not target:
        return jsonify({"error": "target is required"}), 400
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, str(count), target],
            capture_output=True, text=True, timeout=30
        )
        return jsonify({"output": result.stdout + result.stderr, "ok": result.returncode == 0})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "Ping timed out.", "ok": False})
    except Exception as e:
        return jsonify({"output": str(e), "ok": False})

@app.route("/api/tools/traceroute", methods=["POST"])
@login_required
def tool_traceroute():
    data   = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    if platform.system().lower() == "windows":
        cmd = ["tracert", target]
    else:
        cmd = ["traceroute", "-m", "20", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return jsonify({"output": result.stdout + result.stderr, "ok": result.returncode == 0})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "Traceroute timed out after 60 seconds.", "ok": False})
    except FileNotFoundError:
        return jsonify({"output": "traceroute not found. Install with: apt install traceroute", "ok": False})
    except Exception as e:
        return jsonify({"output": str(e), "ok": False})

@app.route("/api/tools/dns", methods=["POST"])
@login_required
def tool_dns():
    data   = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    lines = []
    try:
        # forward lookup
        results = socket.getaddrinfo(target, None)
        ips = list({r[4][0] for r in results})
        lines.append(f"Forward lookup: {target}")
        for ip in ips:
            lines.append(f"  → {ip}")
        # reverse lookup for each IP
        lines.append("")
        lines.append("Reverse lookup:")
        for ip in ips:
            try:
                host = socket.gethostbyaddr(ip)[0]
                lines.append(f"  {ip} → {host}")
            except:
                lines.append(f"  {ip} → (no PTR record)")
        return jsonify({"output": "\n".join(lines), "ok": True})
    except socket.gaierror as e:
        return jsonify({"output": f"DNS resolution failed: {e}", "ok": False})
    except Exception as e:
        return jsonify({"output": str(e), "ok": False})

@app.route("/api/tools/portscan", methods=["POST"])
@login_required
def tool_portscan():
    data       = request.json or {}
    target     = data.get("target", "").strip()
    port_input = data.get("port_input", "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400

    # parse flexible port input: single, comma-separated, ranges, or default
    def parse_ports(s):
        if not s:
            return [21,22,23,25,53,80,110,143,161,389,443,465,514,587,
                    636,993,995,3306,3389,5432,8080,8443,8888,9000,10000]
        ports = set()
        for part in s.replace(' ', '').split(','):
            if '-' in part:
                try:
                    a, b = part.split('-', 1)
                    start, end = int(a), int(b)
                    if start > end: start, end = end, start
                    # cap range at 1000 ports to prevent abuse
                    if end - start > 1000:
                        end = start + 1000
                    ports.update(range(start, end + 1))
                except ValueError:
                    pass
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    pass
        return sorted(ports)

    ports = parse_ports(port_input)
    if not ports:
        return jsonify({"error": "No valid ports specified"}), 400
    if len(ports) > 2000:
        return jsonify({"error": "Too many ports — maximum 2000 per scan"}), 400

    results = []
    lock = threading.Lock()
    def scan_port(port):
        try:
            sock = socket.create_connection((target, port), timeout=1)
            sock.close()
            with lock: results.append({"port": port, "open": True})
        except:
            with lock: results.append({"port": port, "open": False})

    threads = [threading.Thread(target=scan_port, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    results.sort(key=lambda x: x["port"])
    open_ports   = [r for r in results if r["open"]]
    closed_ports = [r for r in results if not r["open"]]
    lines = [f"Port scan results for {target}  ({len(ports)} ports scanned)", "="*50]
    lines.append(f"Open ports ({len(open_ports)}):")
    if open_ports:
        for r in open_ports:
            service = COMMON_PORTS.get(r["port"], "")
            lines.append(f"  ✓ {r['port']:<6}  {service}")
    else:
        lines.append("  (none)")
    if closed_ports:
        lines.append(f"\nClosed/filtered ({len(closed_ports)}):")
        for r in closed_ports:
            service = COMMON_PORTS.get(r["port"], "")
            lines.append(f"  ✗ {r['port']:<6}  {service}")
    return jsonify({"output": "\n".join(lines), "results": results, "ok": True})

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 161:"SNMP", 389:"LDAP",
    443:"HTTPS", 465:"SMTPS", 514:"Syslog", 587:"SMTP",
    636:"LDAPS", 993:"IMAPS", 995:"POP3S", 3306:"MySQL",
    3389:"RDP", 5432:"PostgreSQL", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 8888:"HTTP-Dev", 9000:"Admin", 10000:"Webmin",
}

# ── telnet terminal ───────────────────────────────────────────────────────────
telnet_sessions = {}  # sid -> socket

if SOCKETIO_AVAILABLE:
    @socketio.on("telnet_connect")
    def handle_telnet_connect(data):
        if "username" not in session:
            emit("telnet_error", {"message": "Not authenticated"})
            return
        host = data.get("host", "").strip()
        port = int(data.get("port", 23))
        if not host:
            emit("telnet_error", {"message": "Host is required"})
            return
        try:
            sock = socket.create_connection((host, port), timeout=10)
            sock.setblocking(False)
            sid = request.sid
            telnet_sessions[sid] = sock
            emit("telnet_connected", {"host": host, "port": port})

            def read_output():
                import gevent, select as sel
                while True:
                    gevent.sleep(0.01)
                    try:
                        ready, _, _ = sel.select([sock], [], [], 0.01)
                        if ready:
                            chunk = sock.recv(4096)
                            if not chunk:
                                socketio.emit("telnet_disconnected", {"reason": "Connection closed by host"}, to=sid)
                                break
                            socketio.emit("telnet_output", {"data": chunk.decode("utf-8", errors="replace")}, to=sid)
                    except Exception:
                        socketio.emit("telnet_disconnected", {"reason": "Connection lost"}, to=sid)
                        break
                telnet_sessions.pop(sid, None)
                try: sock.close()
                except: pass

            socketio.start_background_task(read_output)
        except socket.timeout:
            emit("telnet_error", {"message": f"Connection to {host}:{port} timed out"})
        except ConnectionRefusedError:
            emit("telnet_error", {"message": f"Connection refused — {host}:{port} not reachable"})
        except Exception as e:
            emit("telnet_error", {"message": str(e)})

    @socketio.on("telnet_input")
    def handle_telnet_input(data):
        if "username" not in session: return
        sock = telnet_sessions.get(request.sid)
        if sock:
            try: sock.send(data.get("data", "").encode("utf-8", errors="replace"))
            except: pass

    @socketio.on("telnet_disconnect_request")
    def handle_telnet_disconnect():
        sid  = request.sid
        sock = telnet_sessions.pop(sid, None)
        if sock:
            try: sock.close()
            except: pass
        emit("telnet_disconnected", {"reason": "Disconnected by user"})

# ── TFTP server ───────────────────────────────────────────────────────────────
tftp_server_thread  = None
tftp_server_running = False
tftp_server_config  = {"port": 6969, "root": str(UPLOADS), "enabled": False}
TFTP_CONFIG_FILE    = DATA / "tftp_config.json"

def _load_tftp_config():
    global tftp_server_config
    saved = read_json(TFTP_CONFIG_FILE, {})
    if saved:
        tftp_server_config.update(saved)
    tftp_server_config["enabled"] = False  # always start disabled

_load_tftp_config()

@app.route("/api/tools/tftp/status")
@login_required
def tftp_status():
    return jsonify({**tftp_server_config, "running": tftp_server_running})

@app.route("/api/tools/tftp/config", methods=["POST"])
@login_required
def tftp_config():
    global tftp_server_config
    data = request.json or {}
    tftp_server_config["port"] = int(data.get("port", tftp_server_config["port"]))
    tftp_server_config["root"] = data.get("root", tftp_server_config["root"])
    write_json(TFTP_CONFIG_FILE, {
        "port": tftp_server_config["port"],
        "root": tftp_server_config["root"],
    })
    return jsonify(tftp_server_config)

@app.route("/api/tools/tftp/start", methods=["POST"])
@login_required
def tftp_start():
    global tftp_server_thread, tftp_server_running, tftp_server_config
    if tftp_server_running:
        return jsonify({"error": "TFTP server already running"}), 400
    try:
        import tftpy
        root = tftp_server_config.get("root", str(UPLOADS))
        port = int(tftp_server_config.get("port", 6969))
        if not os.path.isdir(root):
            return jsonify({"error": f"Root directory not found: {root}"}), 400
        server = tftpy.TftpServer(root)
        def run():
            global tftp_server_running
            tftp_server_running = True
            try:
                server.listen("0.0.0.0", port)
            except Exception as e:
                print(f"TFTP server error: {e}")
            finally:
                tftp_server_running = False
        tftp_server_thread = threading.Thread(target=run, daemon=True)
        tftp_server_thread.start()
        import time; time.sleep(0.5)  # let it start
        tftp_server_config["enabled"] = True
        return jsonify({"ok": True, "port": port, "root": root})
    except ImportError:
        return jsonify({"error": "tftpy not installed — add 'tftpy' to requirements.txt and rebuild"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/tftp/stop", methods=["POST"])
@login_required
def tftp_stop():
    global tftp_server_running, tftp_server_config
    tftp_server_running = False
    tftp_server_config["enabled"] = False
    return jsonify({"ok": True})
@app.route("/api/backups", methods=["GET"])
@login_required
def list_backups():
    device_filter = request.args.get("device", "")
    result = []
    for f in sorted(BACKUPS.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file() and f.suffix in ('.txt', '.cfg', '.conf', '.log', '.backup'):
            if device_filter and not f.name.startswith(device_filter):
                continue
            result.append({
                "filename": f.name,
                "size":     f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    return jsonify(result)

@app.route("/api/backups/<filename>")
@login_required
def get_backup(filename):
    p = BACKUPS / secure_filename(filename)
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    return jsonify({"filename": filename, "content": p.read_text(errors='replace')})

@app.route("/api/backups/<filename>", methods=["DELETE"])
@login_required
def delete_backup(filename):
    p = BACKUPS / secure_filename(filename)
    if not p.exists():
        return jsonify({"error": "Not found"}), 404
    p.unlink()
    return jsonify({"ok": True})

@app.route("/api/backups/diff", methods=["POST"])
@login_required
def diff_backups():
    data = request.json or {}
    f1   = BACKUPS / secure_filename(data.get("file1", ""))
    f2   = BACKUPS / secure_filename(data.get("file2", ""))
    if not f1.exists() or not f2.exists():
        return jsonify({"error": "One or both files not found"}), 404
    lines1 = f1.read_text(errors='replace').splitlines(keepends=True)
    lines2 = f2.read_text(errors='replace').splitlines(keepends=True)
    diff   = list(difflib.unified_diff(lines1, lines2, fromfile=f1.name, tofile=f2.name))
    return jsonify({"diff": "".join(diff), "changed": len(diff) > 0})

@app.route("/api/backups/<filename>/download")
@login_required
def download_backup(filename):
    return send_from_directory(str(BACKUPS), secure_filename(filename), as_attachment=True)

# ── scheduler ─────────────────────────────────────────────────────────────────
scheduler_instance = None

def init_scheduler():
    global scheduler_instance
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        scheduler_instance = BackgroundScheduler()
        scheduler_instance.start()
        # load saved schedules
        schedules = read_json(SCHEDULES_FILE, {})
        for sid, s in schedules.items():
            if s.get("enabled", True):
                _add_scheduler_job(sid, s)
        import atexit
        atexit.register(lambda: scheduler_instance.shutdown(wait=False))
    except ImportError:
        pass  # APScheduler not installed — scheduling disabled

def _add_scheduler_job(sid, s):
    if not scheduler_instance:
        return
    try:
        from apscheduler.triggers.cron import CronTrigger
        scheduler_instance.add_job(
            func     = _run_scheduled,
            trigger  = CronTrigger.from_crontab(s["cron"]),
            args     = [sid],
            id       = sid,
            replace_existing = True,
        )
    except Exception as e:
        print(f"Scheduler error for {sid}: {e}")

def _run_scheduled(sid):
    schedules = read_json(SCHEDULES_FILE, {})
    s = schedules.get(sid)
    if not s or not s.get("enabled"):
        return
    # build a fake request context to reuse run logic
    all_devices = read_json(DEVICES_FILE, {})
    device_names = resolve_targets(s["target_type"], s.get("target_value",""), s.get("devices",[]))
    script_path  = SCRIPTS / s["filename"]
    if not script_path.exists() or not device_names:
        return
    script_body = script_path.read_text()
    ext = Path(s["filename"]).suffix.lower()
    all_env = read_json(ENV_VARS_FILE, {})
    env_vars_for_script = {k: v["value"] for k, v in all_env.items()}
    devices_for_script = {}
    for k, v in all_devices.items():
        d = dict(v)
        d["password"]  = decrypt(d.pop("password_enc",  ""))
        d["api_token"] = decrypt(d.pop("api_token_enc", ""))
        devices_for_script[k] = d
    files_helper = f"""
import os as _os
class _Files:
    _dir = {json.dumps(str(UPLOADS))}
    def path(self, name):
        p = _os.path.join(self._dir, name)
        if not _os.path.exists(p): raise FileNotFoundError(f"File '{{name}}' not found.")
        return p
    def read(self, name):
        with open(self.path(name)) as f: return f.read()
    def lines(self, name):
        return [l.rstrip('\\n') for l in self.read(name).splitlines() if l.strip()]
    def exists(self, name):
        return _os.path.exists(_os.path.join(self._dir, name))
files = _Files()
"""
    hist = read_json(HISTORY_FILE, [])
    for dev_name in device_names:
        if dev_name not in devices_for_script:
            continue
        device_ctx = devices_for_script[dev_name]
        try:
            if ext == '.sh':
                env = os.environ.copy()
                env.update({'DEVICE_NAME': device_ctx['name'], 'DEVICE_IP': device_ctx['ip'],
                            'DEVICE_PORT': str(device_ctx['port']), 'DEVICE_USERNAME': device_ctx['username'],
                            'DEVICE_PASSWORD': device_ctx['password'], 'DEVICE_TOKEN': device_ctx['api_token'],
                            'FILES_DIR': str(UPLOADS)})
                for k, v in env_vars_for_script.items():
                    env[f'NW_{k}'] = v
                proc = subprocess.run(['bash', str(script_path)], capture_output=True, text=True, timeout=30, cwd=str(BASE), env=env)
            else:
                wrapper = f"""import sys, json
device   = {json.dumps(device_ctx)}
devices  = {json.dumps(devices_for_script)}
env_vars = {json.dumps(env_vars_for_script)}
{files_helper}
{script_body}
"""
                with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
                    tmp.write(wrapper); tmp_path = tmp.name
                proc = subprocess.run([sys.executable, tmp_path], capture_output=True, text=True, timeout=30, cwd=str(BASE))
                os.unlink(tmp_path)
            ok     = proc.returncode == 0
            output = (proc.stdout + proc.stderr).strip()
        except Exception as e:
            ok, output = False, str(e)
        hist.append({"script": s["filename"], "device": dev_name, "ok": ok,
                     "ts": datetime.now().isoformat(), "user": "scheduler",
                     "target_type": s["target_type"], "target_value": s.get("target_value",""),
                     "scheduled": True, "schedule_id": sid})
    write_json(HISTORY_FILE, hist[-500:])
    # update last_run
    schedules = read_json(SCHEDULES_FILE, {})
    if sid in schedules:
        schedules[sid]["last_run"] = datetime.now().isoformat()
        write_json(SCHEDULES_FILE, schedules)

@app.route("/api/schedules", methods=["GET"])
@login_required
def get_schedules():
    return jsonify(read_json(SCHEDULES_FILE, {}))

@app.route("/api/schedules", methods=["POST"])
@login_required
def create_schedule():
    data = request.json or {}
    name = data.get("name","").strip()
    cron = data.get("cron","").strip()
    fname= data.get("filename","").strip()
    if not name or not cron or not fname:
        return jsonify({"error": "name, cron, and filename are required"}), 400
    # validate cron
    try:
        from apscheduler.triggers.cron import CronTrigger
        CronTrigger.from_crontab(cron)
    except Exception as e:
        return jsonify({"error": f"Invalid cron expression: {e}"}), 400
    sid = f"sched_{secrets.token_hex(6)}"
    schedules = read_json(SCHEDULES_FILE, {})
    schedules[sid] = {
        "id":           sid,
        "name":         name,
        "cron":         cron,
        "filename":     fname,
        "target_type":  data.get("target_type",  "devices"),
        "target_value": data.get("target_value", ""),
        "devices":      data.get("devices",       []),
        "enabled":      True,
        "created":      datetime.now().isoformat(),
        "last_run":     None,
    }
    write_json(SCHEDULES_FILE, schedules)
    _add_scheduler_job(sid, schedules[sid])
    return jsonify(schedules[sid])

@app.route("/api/schedules/<sid>/toggle", methods=["POST"])
@login_required
def toggle_schedule(sid):
    schedules = read_json(SCHEDULES_FILE, {})
    if sid not in schedules:
        return jsonify({"error": "Not found"}), 404
    schedules[sid]["enabled"] = not schedules[sid].get("enabled", True)
    write_json(SCHEDULES_FILE, schedules)
    if schedules[sid]["enabled"]:
        _add_scheduler_job(sid, schedules[sid])
    elif scheduler_instance:
        try: scheduler_instance.remove_job(sid)
        except: pass
    return jsonify(schedules[sid])

@app.route("/api/schedules/<sid>", methods=["DELETE"])
@login_required
def delete_schedule(sid):
    schedules = read_json(SCHEDULES_FILE, {})
    if sid not in schedules:
        return jsonify({"error": "Not found"}), 404
    del schedules[sid]
    write_json(SCHEDULES_FILE, schedules)
    if scheduler_instance:
        try: scheduler_instance.remove_job(sid)
        except: pass
    return jsonify({"ok": True})

# ── webhook engine ───────────────────────────────────────────────────────────
import hashlib, hmac as _hmac

def fire_webhooks(event, payload):
    """Fire all enabled outbound webhooks matching the given event. Non-blocking."""
    def _send():
        webhooks = read_json(WEBHOOKS_FILE, {})
        for wh in webhooks.values():
            if wh.get("direction") != "outbound": continue
            if not wh.get("enabled", True): continue
            if event not in wh.get("events", []): continue
            url    = wh.get("url", "")
            secret = wh.get("secret", "")
            if not url: continue
            try:
                import requests as _req
                body    = json.dumps({"event": event, **payload})
                headers = {"Content-Type": "application/json",
                           "X-Network-Wizard-Event": event}
                if secret:
                    sig = _hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
                    headers["X-Network-Wizard-Signature"] = f"sha256={sig}"
                _req.post(url, data=body, headers=headers, timeout=5)
            except Exception as e:
                print(f"[webhook] failed to send to {url}: {e}")
    threading.Thread(target=_send, daemon=True).start()

# ── webhook routes ────────────────────────────────────────────────────────────
@app.route("/api/webhooks", methods=["GET"])
@login_required
def get_webhooks():
    return jsonify(read_json(WEBHOOKS_FILE, {}))

@app.route("/api/webhooks", methods=["POST"])
@login_required
def create_webhook():
    data      = request.json or {}
    direction = data.get("direction", "outbound")
    name      = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    wid = f"wh_{secrets.token_hex(6)}"
    whs = read_json(WEBHOOKS_FILE, {})

    if direction == "outbound":
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "url is required for outbound webhooks"}), 400
        whs[wid] = {
            "id":        wid,
            "name":      name,
            "direction": "outbound",
            "url":       url,
            "secret":    data.get("secret", ""),
            "events":    data.get("events", ["script_run_failed"]),
            "enabled":   True,
            "created":   datetime.now().isoformat(),
        }
    else:
        token = secrets.token_urlsafe(24)
        whs[wid] = {
            "id":        wid,
            "name":      name,
            "direction": "inbound",
            "token":     token,
            "actions":   data.get("actions", ["run_script"]),
            "enabled":   True,
            "created":   datetime.now().isoformat(),
            "last_triggered": None,
        }

    write_json(WEBHOOKS_FILE, whs)
    return jsonify(whs[wid])

@app.route("/api/webhooks/<wid>", methods=["PUT"])
@login_required
def update_webhook(wid):
    whs = read_json(WEBHOOKS_FILE, {})
    if wid not in whs:
        return jsonify({"error": "Not found"}), 404
    data = request.json or {}
    wh   = whs[wid]
    wh["name"]    = data.get("name",    wh["name"])
    wh["enabled"] = data.get("enabled", wh["enabled"])
    if wh["direction"] == "outbound":
        wh["url"]    = data.get("url",    wh.get("url",    ""))
        wh["secret"] = data.get("secret", wh.get("secret", ""))
        wh["events"] = data.get("events", wh.get("events", []))
    else:
        wh["actions"] = data.get("actions", wh.get("actions", []))
    write_json(WEBHOOKS_FILE, whs)
    return jsonify(wh)

@app.route("/api/webhooks/<wid>", methods=["DELETE"])
@login_required
def delete_webhook(wid):
    whs = read_json(WEBHOOKS_FILE, {})
    if wid not in whs:
        return jsonify({"error": "Not found"}), 404
    del whs[wid]
    write_json(WEBHOOKS_FILE, whs)
    return jsonify({"ok": True})

@app.route("/api/webhooks/<wid>/test", methods=["POST"])
@login_required
def test_webhook(wid):
    whs = read_json(WEBHOOKS_FILE, {})
    if wid not in whs:
        return jsonify({"error": "Not found"}), 404
    wh = whs[wid]
    if wh["direction"] != "outbound":
        return jsonify({"error": "Can only test outbound webhooks"}), 400
    try:
        import requests as _req
        payload = json.dumps({
            "event":   "test",
            "message": "Test webhook from Network Wizard",
            "ts":      datetime.now().isoformat(),
        })
        headers = {"Content-Type": "application/json",
                   "X-Network-Wizard-Event": "test"}
        secret = wh.get("secret", "")
        if secret:
            sig = _hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            headers["X-Network-Wizard-Signature"] = f"sha256={sig}"
        r = _req.post(wh["url"], data=payload, headers=headers, timeout=5)
        return jsonify({"ok": True, "status": r.status_code, "response": r.text[:500]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/webhooks/<wid>/toggle", methods=["POST"])
@login_required
def toggle_webhook(wid):
    whs = read_json(WEBHOOKS_FILE, {})
    if wid not in whs:
        return jsonify({"error": "Not found"}), 404
    whs[wid]["enabled"] = not whs[wid].get("enabled", True)
    write_json(WEBHOOKS_FILE, whs)
    return jsonify(whs[wid])

# ── inbound webhook receiver ──────────────────────────────────────────────────
@app.route("/api/webhooks/receive/<token>", methods=["POST"])
def receive_webhook(token):
    """Public endpoint — receives inbound webhooks from external systems."""
    whs = read_json(WEBHOOKS_FILE, {})
    # find matching inbound webhook by token
    wh = next((w for w in whs.values()
                if w.get("direction")=="inbound" and w.get("token")==token), None)
    if not wh:
        return jsonify({"error": "Invalid token"}), 401
    if not wh.get("enabled", True):
        return jsonify({"error": "Webhook disabled"}), 403

    data    = request.json or {}
    action  = data.get("action", "")
    allowed = wh.get("actions", [])

    if action not in allowed:
        return jsonify({"error": f"Action '{action}' not allowed for this webhook"}), 400

    # update last triggered
    whs[wh["id"]]["last_triggered"] = datetime.now().isoformat()
    write_json(WEBHOOKS_FILE, whs)

    # ── execute action ────────────────────────────────────────────────────────
    if action == "run_script":
        fname  = data.get("script", "")
        target = data.get("target", "")
        if not fname or not target:
            return jsonify({"error": "script and target are required"}), 400
        sp = SCRIPTS / fname
        if not sp.exists():
            return jsonify({"error": f"Script '{fname}' not found"}), 404
        devices  = read_json(DEVICES_FILE, {})
        all_env  = read_json(ENV_VARS_FILE, {})
        env_vars = {k: v["value"] for k, v in all_env.items()}
        dev_ctx  = devices.get(target)
        if not dev_ctx:
            return jsonify({"error": f"Device '{target}' not found"}), 404
        d = dict(dev_ctx)
        d["password"]  = decrypt(d.pop("password_enc", ""))
        d["api_token"] = decrypt(d.pop("api_token_enc", ""))
        result = _execute_script_on_device(d, {target: d}, env_vars, sp, sp.read_text(), {}, "", False)
        fire_webhooks("script_run_complete", {
            "script": fname, "device": target,
            "ok": result["ok"], "triggered_by": "webhook",
        })
        return jsonify({"ok": True, "result": result})

    elif action == "check_device":
        name = data.get("device", "")
        if not name:
            return jsonify({"error": "device is required"}), 400
        devices = read_json(DEVICES_FILE, {})
        d = devices.get(name)
        if not d:
            return jsonify({"error": f"Device '{name}' not found"}), 404
        try:
            sock = socket.create_connection((d["ip"], int(d["port"])), timeout=3)
            sock.close()
            status = "online"
        except:
            status = "offline"
        d["status"] = status
        devices[name] = d
        write_json(DEVICES_FILE, devices)
        if status == "offline":
            fire_webhooks("device_offline", {"device": name, "ip": d["ip"]})
        return jsonify({"ok": True, "device": name, "status": status})

    elif action == "add_note":
        name    = data.get("device", "")
        message = data.get("message", "").strip()
        if not name or not message:
            return jsonify({"error": "device and message are required"}), 400
        devices = read_json(DEVICES_FILE, {})
        if name not in devices:
            return jsonify({"error": f"Device '{name}' not found"}), 404
        note = {"ts": datetime.now().isoformat(), "user": "webhook",
                "type": "note", "message": message}
        devices[name].setdefault("notes_log", []).append(note)
        write_json(DEVICES_FILE, devices)
        return jsonify({"ok": True, "note": note})

    elif action == "run_playbook":
        pid    = data.get("playbook_id", "")
        target = data.get("target", "")
        target_type = data.get("target_type", "devices")
        pbs = read_json(PLAYBOOKS_FILE, {})
        if pid not in pbs:
            return jsonify({"error": f"Playbook '{pid}' not found"}), 404
        return jsonify({"ok": True, "message": f"Playbook '{pbs[pid]['name']}' queued",
                        "note": "Full playbook execution via webhook coming soon"})

    return jsonify({"error": f"Unknown action: {action}"}), 400

# ── users ─────────────────────────────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@admin_required
def get_users():
    users = read_json(USERS_FILE, {})
    return jsonify([{"username": k, "role": v["role"], "totp_enabled": v.get("totp_enabled", False)} for k, v in users.items()])

@app.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "operator")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    users = read_json(USERS_FILE, {})
    users[username] = {"password": hash_password(password), "role": role}
    write_json(USERS_FILE, users)
    return jsonify({"username": username, "role": role})

@app.route("/api/users/<username>", methods=["DELETE"])
@admin_required
def delete_user(username):
    if username == session.get("username"):
        return jsonify({"error": "Cannot delete yourself"}), 400
    users = read_json(USERS_FILE, {})
    if username not in users:
        return jsonify({"error": "Not found"}), 404
    del users[username]
    write_json(USERS_FILE, users)
    return jsonify({"ok": True})

if __name__ == "__main__":
    init_scheduler()
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 5000))
    if SOCKETIO_AVAILABLE:
        socketio.run(app, debug=False, host=host, port=port, allow_unsafe_werkzeug=True)
    else:
        app.run(debug=False, host=host, port=port)
