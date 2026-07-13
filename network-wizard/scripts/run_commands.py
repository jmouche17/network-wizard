# Reads commands from an uploaded text file and runs each one
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
