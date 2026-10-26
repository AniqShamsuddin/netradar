# NetRadar

NetRadar is a real-time network intrusion detection system written in Python. It captures live traffic on a home network, identifies every device it sees, and flags suspicious changes that could indicate an attack.

I built it to work alongside my Pi-hole DNS server on my homelab, so I could see not just which domains my devices look up, but what is actually happening on the network in real time.

## What it does

- Captures live network traffic using Scapy
- Filters out its own SSH traffic at the kernel level with a BPF filter, so the output stays focused on real network activity
- Labels each IPv4 packet with its source, destination, protocol (TCP, UDP, or other), and destination port
- Distinguishes ARP requests ("who has this IP?") from ARP replies ("this IP is at this MAC")
- Discovers devices on the network by recording each IP address and MAC address it sees
- Detects ARP spoofing in two complementary ways: alerting when a known IP suddenly appears with a different MAC address, and when a single MAC address claims more than one IP
- Escalates any MAC change involving the router or the Pi-hole DNS server to CRITICAL, since impersonating either one would let an attacker intercept all internet or DNS traffic
- Identifies device manufacturers (for example Apple, Amazon, eero) using the official IEEE OUI registry
- Saves each capture to a `.pcap` file for deeper analysis in Wireshark
- Detects TCP port scans by counting how many different ports each source tries to open within a 60 second window, counting only new connection attempts (SYN without ACK) so normal replies are never mistaken for scans
- Uses a cooldown on every detection so an ongoing attack produces one clear alert instead of hundreds 
- Quiet mode by default: only alerts are printed, so warnings are never buried in routine traffic

## Alert levels

- **INFO:** good to know, such as a new device joining the network
- **WARNING:** worth investigating, such as a port scan or a regular device changing its MAC address
- **CRITICAL:** act now, such as something impersonating the router or the DNS server

## How it works

Scapy captures packets from the network interface, and each packet is passed to a handler function as it arrives. Non-IP packets are handled first by a guard clause, which labels ARP traffic and summarizes everything else. Devices are tracked in a dictionary that maps IP addresses to MAC addresses, which persists for the whole run so each device is only announced once. Vendor names come from the IEEE OUI registry, which is loaded into a dictionary once at startup so every lookup is instant and happens locally.

## Setup

```bash
git clone https://github.com/AniqShamsuddin/netradar.git
cd netradar
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
wget -O oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

## Usage

```bash
sudo .venv/bin/python sniffer.py
```

Capturing raw network traffic is a privileged action, so the script must run as root with `sudo`. The full path to the virtual environment's Python is used because `sudo` does not inherit the activated environment.

By default NetRadar runs in quiet mode and prints only alerts. Settings near the top of `sniffer.py` control its behavior: `VERBOSE` shows every packet for debugging, `PORT_SCAN_THRESHOLD` and `PORT_SCAN_WINDOW` tune port scan sensitivity, `ALERT_COOLDOWN` sets how long to wait before repeating an alert, and `PROTECTED_IPS` lists the critical devices on your network.

## Security notes

- Vendor lookups happen locally. Device MAC addresses are never sent to an outside service.
- Capture files (`.pcap`) are excluded from the repository with `.gitignore`, since they contain private network data.
- The OUI registry is downloaded during setup rather than committed, so it stays current and the repository stays small.

## Roadmap

- **Phase 3: Detections** for SYN floods, and learning devices from IP traffic as well as ARP (port scan and ARP spoofing detection are complete)
- **Phase 4: Live dashboard** with a real-time network map in the browser
- **Phase 5: Attack lab** to test each detection against simulated attacks on my own network

## Disclaimer

Only run NetRadar on networks you own or have explicit permission to monitor. Capturing traffic on networks without authorization may be illegal.
