import ipaddress
import socket
import struct
import sys
import argparse
import csv
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
import time 
import statistics
import csv
import traceback

src_ip = "aggregate_traffic"
window_length = 0.05
windows = {}
dataset = []
feature_rows = []

# Creates aruments to create commands that will execute the protocols
network_parser = argparse.ArgumentParser(description='Packet Inspection')
network_parser.add_argument('--ip', help='IP address to sniff on', required=True)
network_parser.add_argument('--data', help='Display data', action='store_true')
network_parser.add_argument('--proto', choices=['icmp', 'tcp', 'udp', 'arp', 'all'],
							default='all', help='Protocol to sniff on')
# Parses command-line arguments and stores them as different options to call specfic protocols
options  = network_parser.parse_args()

local_ip = options.ip if options.ip != "0.0.0.0" else None

def new_window(start_time):
    return {
        "start_time": start_time,
        "packet_count": 0,
        "byte_count": 0,
        "protocol_count": {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "IPv4": 0,
            "IPv6": 0
        },
        "inbound_count": 0,
        "outbound_count": 0,
        "src_ports": set(),
        "dst_ports": set(),
        "mac_addresses": set(),
        "arp_count": 0,
        "timestamps": []
    }

def extract_features(window, now):
    duration = now - window["start_time"]

    packet_count = window["packet_count"]
    byte_count = window["byte_count"]

    avg_packet_size = byte_count / packet_count if packet_count else 0
    packets_per_second = packet_count / duration if duration > 0 else 0

    tcp = window["protocol_count"]["TCP"]
    udp = window["protocol_count"]["UDP"]
    icmp = window["protocol_count"]["ICMP"]
    arp = window["protocol_count"]["ARP"]

    in_out_ratio = (
        window["inbound_count"] / max(window["outbound_count"], 1)
    )

    fluctuation = 0
    if len(window["timestamps"]) > 1:
        diffs = [
            window["timestamps"][i+1] - window["timestamps"][i]
            for i in range(len(window["timestamps"]) - 1)
        ]
        fluctuation = statistics.stdev(diffs) if len(diffs) > 1 else 0

    return [
        packet_count,
        byte_count,
        avg_packet_size,
        tcp,
        udp,
        icmp,
        arp,
        len(window["dst_ports"]),
        packets_per_second,
        in_out_ratio,
        fluctuation
    ]

# Labelling
def assign_label(features):
    packet_count = features[0]
    tcp = features[3]
    udp = features[4]
    icmp = features[5]
    arp = features[6]
    unique_ports = features[7]
    packets_per_sec = features[8]

	label = 0

    if arp > 5:
        return label = max(label, 1)  # ARP anomaly
    if icmp > 10:
        return label = max(label, 2)  # ICMP flood
    if udp > 10:
        return label = max(label, 3)  # UDP flood
	if tcp > 10:
		return label = max(label, 4)
    if unique_ports > 20:
        return label = max(label, 5)  # Port scan
    return label # Normal

def update_window(src_ip, packet_len, protocol, src_port, dst_port, src_mac, direction, now):
    global windows
    print("Update window:", src_ip)
    if src_ip not in windows:
    	windows[src_ip] = new_window(now)
    	
    window = windows[src_ip]
    
    # Update basic counters
    window["packet_count"] += 1
    window["byte_count"] += packet_len

    print("windows update:", src_ip)

    # Update protocol counts
    if protocol and protocol in window["protocol_count"]:
        window["protocol_count"][protocol] += 1

    # Update direction
    if direction == "in":
        window["inbound_count"] += 1
    else:
        window["outbound_count"] += 1

    # Update ports (if applicable)
    if src_port is not None:
        window["src_ports"].add(src_port)
    if dst_port is not None:
        window["dst_ports"].add(dst_port)

    # Update MAC tracking
    window["mac_addresses"].add(src_mac)

    # Timing for changes for the rate of traffic
    window["timestamps"].append(now)

    window = windows[src_ip]
    
    print("Window age:", now - window["start_time"])
    
    if now - window["start_time"] >= window_length:
        features = extract_features(window, now)
        label = assign_label(features)
        row = features + [label]

        # Store or print features (for ML later)
        feature_rows.append(row)
        
        print("Feature row:", row)

        # Reset window
        del windows[src_ip]
        
    print("windows statistics:", window["packet_count"], "packets")     
   

# CSV/Pandas
FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "arp_count",
    "unique_dst_ports",
    "packets_per_second",
    "in_out_ratio",
    "fluctuation",
    "label"
]

class Packet:
	def __init__(self, data):
		self.packet =  data
		# Contains the header data in big endian
		header = struct.unpack('!BBHHHBBH4s4s', self.packet[0:20])
		# Contains values for different sections of the header
		self.version = header[0] >> 4
		self.header_length = (header[0] & 0xF) * 4
		self.type_of_service = header[1]
		self.packet_length = header[2]
		self.fragment_indentifier = header[3]
		self.offset = header[4]
		self.time_to_live = header[5]
		self.protocol_number = header[6]
		self.checksum = header[7]
		self.source = header[8]
		self.destination = header[9]

		# Provides the IP source and destination address
		self.source_addr = ipaddress.ip_address(self.source)
		self.destination_addr = ipaddress.ip_address(self.destination)

		# Contains the length of the header
		self.payload = data[self.header_length:]

		# Maps the different level 3 protocols
		self.protocol_map = {1: "ICMP", 6:"TCP", 17:"UDP"}

		# Maps protocol number so that it can find a match
		try:
			self.protocol = self.protocol_map[self.protocol_number]
		except Exception as e:
			print(f'{e} No protocol for [self.protocol_number]')
			self.protocol = str(self.protocol_number)

	# Prints protocol source and destination address
	def print_header_short(self):
		print(f'Protocol: {self.protocol} {self.source_addr} -> {self.destination_addr}')


	def print_data(self):
		# Converts IP header length from 32 bits to bytes
		self.header_length_bytes = self.header_length * 4
		# Extracts the payload from TCP, UDP, ICMP data
		self.payload = self.packet[self.header_length_bytes:]

		# Stores UDP data
		udp = UDP(self.payload)

		# Searches for ASCII characters in the packet payload
		print('*'*10 + 'ASCII START' + '*'*10)
		for b in self.payload:
			if b < 128:
				print(chr(b), end='')
			else:
				print('.', end='')
		print('*'*10 + 'ASCII END' + '*'*10)

class UDP_DATA:
	# Extracts packet contents to see if it's a UDP packet
	def __init__(self, data):
		self.source_port, self.destination_port, self.length, self.checksum = \
		struct.unpack('!HHHH', data[:8])
		self.data = data[8:]

def format_mac(addr: bytes) -> str:
	return ':'.join(f'{b:02x}' for b in addr)  

class Ethernet:
	# Extracts packet contents to extract ethernet frames
	def __init__(self, data):
		dst, src, proto = struct.unpack('!6s6sH', data[:14])
		self.src_mac = format_mac(src)
		self.dst_mac = format_mac(dst)
		self.proto = socket.ntohs(proto)
		self.payload = data[14:]

class ARP_DATA:
    def __init__(self, data):
		# Contains values for different sections of the header for ARP
        (
            self.htype,
            self.ptype,
            self.hlen,
            self.plen,
            self.op,
            self.src_mac,
            self.src_ip,
            self.dst_mac,
            self.dst_ip
        ) = struct.unpack('!HHBBH6s4s6s4s', data[:28]) # Contains the header data in big endian for arp

	# Provides the IP source and destination address for ARP
        self.src_ip = socket.inet_ntoa(self.src_ip)
        self.dst_ip = socket.inet_ntoa(self.dst_ip)

	# Prints protocol source and destination address for ARP
    def print_summary(self):
        op = "REQUEST" if self.op == 1 else "REPLY"
        print(f"ARP {op}: {self.src_ip} → {self.dst_ip}")

def packet_processing(pkt):
	print("packet received")
	now = time.time()
	
	if pkt.haslayer(IP):
		src_ip = pkt["IP"].src
		dst_ip = pkt["IP"].dst
		packet_len = len(pkt)
		
		protocol = None
		src_port = None
		dst_port = None
		
		if pkt.haslayer(TCP):
			protocol = "TCP"
			src_port = pkt[TCP].sport
			dst_port = pkt[TCP].dport
			
		elif pkt.haslayer(UDP):
			protocol = "UDP"
			src_port = pkt[UDP].sport
			dst_port = pkt[UDP].dport
			
		elif pkt.haslayer(ICMP):
			protocol = "ICMP"
			
		src_mac = pkt.src if hasattr(pkt, "src") else None
		
		direction = "out"
		if local_ip is not None and dst_ip == local_ip:
			direction = "in"
		
		print("IP layer detected")
		print("Direction:", direction)
		print("Detected protocol:", protocol) 
		
		try: 
			print("Updating window")
			update_window(
				src_ip = src_ip,
				packet_len = packet_len,
				protocol = protocol,
				src_port = src_port,
				dst_port = dst_port,
				src_mac = src_mac,
				direction = direction,
				now = now,
				)
		except Exception as e:
			traceback.print_exc()
			
	elif pkt.haslayer(ARP):
		protocol = "ARP"
		src_ip = pkt.psrc
		dst.ip = pkt.pdst
		packet_len = len(pkt)
		src_port = None
		dst_port = None
		src_mac = pkt[ARP].hwsrc
		
		direction = "out"
		if local_ip is not None and dst_ip == local_ip:
			direction = "in"
		
def csv_dataset(filename="traffic_patterns.csv"):
	global windows, feature_rows
	
	print("Extracting features...")
	
	for src_ip, window in windows.items():
		features = extract_features(window, time.time())
		label = assign_label(features)
		row = features + [label]
		feature_rows.append(row)
		
	print("Writing CSV file...")
	
	with open(filename, "w", newline="") as f:
		writer = csv.writer(f)
		writer.writerow(FEATURE_NAMES)
		writer.writerows(feature_rows)
	print("Dataset saved:", filename)
				
def inspection(target_host):
	print('Sniffer started')
	
	try:
		sniff(prn=packet_processing, store=False)
		
	except KeyboardInterrupt:
		print("Stopping sniffer...")
	finally:
		csv_dataset()
		print("Dataset created")
		sys.exit(0)

if __name__ == '__main__':
	inspection(options.ip)
