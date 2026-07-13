# Interface info — uses api_token for Bearer auth
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
