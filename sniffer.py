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


















from scapy.all import sniff, IP, TCP, UDP, ARP, wrpcap

def handle_packet(packet):
    if not packet.haslayer(IP):
        if packet.haslayer(ARP):
           print(f"ARP | {packet[ARP].psrc} asking about {packet[ARP].pdst}")
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
