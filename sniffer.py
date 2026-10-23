# sniffer.py
# Goal: capture 20 packets and print source IP, destination IP, and protocol

# INPUT: Handling each packet as it arrives for real time intrusion detection service 
#

# PROCESS:
#1. Check: does this packet have an ip layer
#2. If No: print "Not an IP packet" and stop handling this packet 
#3. If Yes: pull out the source IP and destination IP
#4. Check: does the packet have a TCP layer
#If yes, protocol is "TCP" and grab the destination port
#5. Otherwise, check: does it have a UDP layer
# If yes, protocol is "UDP" and grab the destination port 
#6. Otherwise, protocol is "Other" (no port to show)
#7. Print one line with everything collected 

# OUTPUT: source ip, destination ip, port number, what protocol it is being sent on
#192.168.4.172 -> 8.8.8.8 | UDP | port 53
#192.168.4.172 -> 8.8.8.8 | TCP | port 443
#Not an IP packet
#192.168.4.172 -> 8.8.8.8 | Other

# EDGE CASES: Print "Not an IP Packet" and stop handling the packet 

# PHASE 2: DEVICE DISCOVERY
# Goal: track every device on the network by IP and MAC

# STORAGE:
# the storage is kept in the dictionary, which is created outside the function, 
# with IP keys and MACs as values

# PROCESS (for each ARP packet):
# 1. Get the sender's IP from psrc and the sender's MAC from hwsrc
# 2. If the IP is 0.0.0.0, skip it (a device with no address yet)
# 3. Check: is this IP already a key in the dictionary?
# 4. If NO: add the IP and MAC to the dictionary, then print New device discovered / Mapping added
# 5. If YES: compare the stored MAC to the MAC in this packet
#    - If they're the same: do nothing and continue (does anything need to happen?)
#    - If they're different: print a WARNING, keep the old MAC in the dictionary
#      (FUTURE: let the user approve the new MAC, e.g. from the dashboard)

# OUTPUT:
# (example lines for each case that p# Case 4 (New device discovered):
#[INFO] New device discovered: 192.168.4.50 -> 00:0c:29:ab:cd:ef

# Case 5 - Different MAC (IP Conflict / Spoofing Alert):
#[WARNING] IP conflict detected! IP 192.168.4.50 is already mapped to 00:0c:29:ab:cd:ef,
# but packet shows MAC aa:bb:cc:dd:ee:ff. Dictionary updated.
#rints something)

# EDGE CASES:
# DHCP traffic came from 0.0.0.0, a device without an address, sends an ARP with sender IP 0.0.0.0,
#this should not go into device list until ip address is given 


# PHASE 3: PORT SCAN DETECTION (version 1)
# Goal: flag any source that tries to connect to many different ports

# SETTINGS:
# PORT_SCAN_THRESHOLD = 15

# STORAGE:
# ports_seen: a dictionary created outside the function
#   Key: source IP    Value: a set of destination ports (sets ignore duplicates)
# flagged_scanners: a set of source IPs that were already reported

# PROCESS (for each TCP packet):
# 1. Only continue if the TCP flags are exactly "S" (a new connection attempt)
# 2. Get the source IP and the destination port
# 3. If this source IP is not in ports_seen yet, give it an empty set
# 4. Add the destination port to that source's set
# 5. Check: is the number of different ports greater than PORT_SCAN_THRESHOLD?
# 6. If yes, AND the source is not in flagged_scanners:
#    print a WARNING, then add the source to flagged_scanners
# 7. If it was already flagged: do nothing (one alert per scanner, avoids alert fatigue)

# OUTPUT:
# [WARNING] Possible port scan from 192.168.4.99: 16 different ports contacted

# EDGE CASES:
# - Replies (SYN-ACK or ACK) go to many ephemeral ports, so only SYN packets
#   are counted. Otherwise the homelab would flag itself just for replying.
# - Repeated packets to the same port (like SSH on 22) count once, thanks to the set.
# - FUTURE: add a time window, and detect slow scans spread over hours or days.













import csv
from scapy.all import sniff, IP, TCP, UDP, ARP
known_devices = {}
vendors = {}
PORT_SCAN_THRESHOLD = 15
ports_seen = {}
flagged_scanners = set()

with open("oui.csv", newline="") as f:   # open the file; it closes itself automatically when done
    reader = csv.reader(f)                # reads the file row by row, handling quoted commas
    next(reader)                          # skips one row (the header line)
    for row in reader:                    # each row is a list of columns
        prefix = row[1]                            # second column (Assignment)
        company = row[2]                            # third column (Organization Name)
        vendors[prefix] = company

print(len(vendors))

def get_vendor(mac):
    prefix = mac.replace(":","").upper()[:6]                     # your one-liner, using mac
    if prefix in vendors:
        return vendors[prefix]                   # look up the company for this prefix
    return "Unknown vendor"

def check_port_scan(source_ip, port):
    if source_ip not in ports_seen:
        ports_seen[source_ip] = set()
    ports_seen[source_ip].add(port)
    port_count = len(ports_seen[source_ip])
    if port_count > PORT_SCAN_THRESHOLD and source_ip not in flagged_scanners :
        print(f"[WARNING] Possible port scan from {source_ip}: {port_count} different ports contacted")
        flagged_scanners.add(source_ip)

def handle_packet(packet):
    if not packet.haslayer(IP):
        if packet.haslayer(ARP):
           ip_address = packet[ARP].psrc
           mac_address = packet[ARP].hwsrc
           if packet[ARP].op == 1:
                print(f"ARP Request | {ip_address} asking who has {packet[ARP].pdst}")
           elif packet[ARP].op == 2:
                print(f"ARP Reply | {ip_address} is at {mac_address}")
           if ip_address == "0.0.0.0":
                return
           if ip_address not in known_devices:
                known_devices[ip_address] = mac_address
                print (f"[INFO] New device discovered: {ip_address} -> {mac_address} ({get_vendor(mac_address)})")
           elif known_devices[ip_address] != mac_address:
                print (f"[WARNING] MAC change for {ip_address}: was {known_devices[ip_address]}, now {mac_address}")
        else:
           print(f"Not an IP Packet | {packet.summary()}")
        return
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    if packet.haslayer(TCP):
       protocol = "TCP"
       port = packet[TCP].dport
       flags = str(packet[TCP].flags)
       if "S" in flags and "A" not in flags:
           check_port_scan(source_ip, port)
       print (f"{source_ip} -> {destination_ip} | {protocol} | port {port}") 
    elif packet.haslayer(UDP):
       protocol = "UDP"
       port = packet[UDP].dport
       print (f"{source_ip} -> {destination_ip} | {protocol} | port {port}")
    else:
       print(f"{source_ip} -> {destination_ip} | Other")

sniff(prn=handle_packet, filter="not port 22", store=False)
