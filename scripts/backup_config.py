# Config backup — saves to backups/ folder, viewable in the Backups tab
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
