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

















from scapy.all import sniff, IP, TCP, UDP, ARP, wrpcap
known_devices = {}

def handle_packet(packet):
    if not packet.haslayer(IP):
        if packet.haslayer(ARP):
           print(f"ARP | {packet[ARP].psrc} asking about {packet[ARP].pdst}")
           ip_address = packet[ARP].psrc
           mac_address = packet[ARP].hwsrc
           if ip_address == "0.0.0.0":
                return
           if ip_address not in known_devices:
                known_devices[ip_address] = mac_address
                print (f"[INFO] New device discovered: {ip_address} -> {mac_address}")
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
       print (f"{source_ip} -> {destination_ip} | {protocol} | port {port}") 
    elif packet.haslayer(UDP):
       protocol = "UDP"
       port = packet[UDP].dport
       print (f"{source_ip} -> {destination_ip} | {protocol} | port {port}")
    else:
       print(f"{source_ip} -> {destination_ip} | Other")

packets = sniff(prn=handle_packet, filter = "not port 22",  count=20)
wrpcap("captured_packets.pcap", packets)
