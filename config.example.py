# NetRadar configuration
# Copy this file to config.py and fill in the values for your network:
#   cp config.example.py config.py

# Print every packet (True) or only alerts (False)
VERBOSE = False

# Port scan detection: alert when one source tries more than this many
# different ports within the window (in seconds)
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 60

# Seconds to wait before repeating an alert about the same source
ALERT_COOLDOWN = 600

# Critical devices on your network. MAC changes for these IPs are CRITICAL.
# Replace these placeholders with your router and other key devices.
PROTECTED_IPS = {
    "192.168.1.1": "router",
    "192.168.1.10": "DNS server",
}
