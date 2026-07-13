# Ping check — injected: device, devices, files
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
