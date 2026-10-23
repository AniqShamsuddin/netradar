# NetRadar

NetRadar is a real-time network intrusion detection system written in Python. It captures live traffic on a home network, identifies every device it sees, and flags suspicious changes that could indicate an attack.

I built it to work alongside my Pi-hole DNS server on my homelab, so I could see not just which domains my devices look up, but what is actually happening on the network in real time.

## What it does

- Captures live network traffic using Scapy
- Filters out its own SSH traffic at the kernel level with a BPF filter, so the output stays focused on real network activity
- Labels each IPv4 packet with its source, destination, protocol (TCP, UDP, or other), and destination port
- Distinguishes ARP requests ("who has this IP?") from ARP replies ("this IP is at this MAC")
- Discovers devices on the network by recording each IP address and MAC address it sees
- Warns when a known IP address suddenly appears with a different MAC address, a possible sign of ARP spoofing
- Identifies device manufacturers (for example Apple, Amazon, eero) using the official IEEE OUI registry
- Saves each capture to a `.pcap` file for deeper analysis in Wireshark

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

## Security notes

- Vendor lookups happen locally. Device MAC addresses are never sent to an outside service.
- Capture files (`.pcap`) are excluded from the repository with `.gitignore`, since they contain private network data.
- The OUI registry is downloaded during setup rather than committed, so it stays current and the repository stays small.

## Roadmap

- **Phase 3: Detections** for port scans, ARP spoofing, and SYN floods
- **Phase 4: Live dashboard** with a real-time network map in the browser
- **Phase 5: Attack lab** to test each detection against simulated attacks on my own network

## Disclaimer

Only run NetRadar on networks you own or have explicit permission to monitor. Capturing traffic on networks without authorization may be illegal.
