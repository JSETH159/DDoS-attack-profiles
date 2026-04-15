import ipaddress
import socket
import struct
import sys
import argparse
import csv
import time
import statistics
import traceback
import threading
import subprocess
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, get_if_list

windows      = {}
feature_rows = []

LABEL_NAMES = {
    0: "Normal",
    1: "Port Scan",
    2: "UDP Flood",
    3: "ICMP Flood",
    4: "ARP Anomaly",
    5: "SYN Flood",
    6: "HTTP Flood",
}

# Window length in 0.5 seconds is long enough to capture packets to detect floods
WINDOW_LENGTH = 0.5
# Maximun packets per second allowed
RATE_LIMIT_PPS = 3000
# Maximum packets allowed before rate limiting is enforced
RATE_LIMIT_PACKETS = 80

# Creates aruments to create commands that will execute the protocol detection
network_parser = argparse.ArgumentParser(description='Packet Inspection & Threat Detection')
network_parser.add_argument('--ip',    help='Local IP address to monitor (use 0.0.0.0 to monitor all)',
                            required=True)
network_parser.add_argument('--data',  help='Display raw ASCII payload data', action='store_true')
network_parser.add_argument('--proto', choices=['icmp', 'tcp', 'udp', 'arp', 'all'],
                            default='all', help='Protocol to sniff')
network_parser.add_argument('--whitelist', nargs='+', default=[], help='Additional IPs to whitelist')
network_parser.add_argument('--out',   help='CSV output filename', default='traffic_patterns.csv')

# Parses command-line arguments and stores them as different options to call specfic protocols
options  = network_parser.parse_args()
local_ip = options.ip if options.ip != "0.0.0.0" else None

# Window management
def new_window(start_time):
    return {
        "start_time":     start_time,
        "packet_count":   0,
        "byte_count":     0,
        "protocol_count": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "IPv4": 0, "IPv6": 0},
        "inbound_count":  0,
        "outbound_count": 0,
        "src_ports":      set(),
        "dst_ports":      set(),
        "mac_addresses":  set(),
        "timestamps":     [],
        # SYN flood: count packets that are pure SYN (no ACK)
        "syn_only_count": 0,
        # HTTP flood: count TCP connections to web ports (80/443/8080/8443)
        "http_count":     0,
    }


def extract_features(window, now):
    # Tracks duration of the time window
    duration = now - window["start_time"]

    packet_count    = window["packet_count"] # Total number of packets
    byte_count      = window["byte_count"] # Total number of bytes for each packet
    # Average size of packets recieved
    avg_packet_size = byte_count / packet_count if packet_count else 0
    # The rate of packets sent to the target host
    packets_per_sec = packet_count / duration   if duration > 0  else 0

    # Keeps track of all protocols that have been used
    tcp  = window["protocol_count"]["TCP"]
    udp  = window["protocol_count"]["UDP"]
    icmp = window["protocol_count"]["ICMP"]
    arp  = window["protocol_count"]["ARP"]

    # Calculates the ratio of inbound to outbound packets
    total_directional = window["inbound_count"] + window["outbound_count"]
    in_out_ratio = (window["inbound_count"] / total_directional
                    if total_directional > 0 else 0.5)

    # Fluctuation: The standard deviation of inter-packet arrival times
    fluctuation = 0.0
    if len(window["timestamps"]) > 2:
        diffs       = [window["timestamps"][i+1] - window["timestamps"][i]
                       for i in range(len(window["timestamps"]) - 1)]
        fluctuation = statistics.stdev(diffs)

    syn_only_count = window["syn_only_count"]
    http_count     = window["http_count"]

    # Dataset features
    return [
        packet_count,              # 0
        byte_count,                # 1
        avg_packet_size,           # 2
        tcp,                       # 3
        udp,                       # 4
        icmp,                      # 5
        arp,                       # 6
        len(window["dst_ports"]),  # 7  unique_dst_ports
        packets_per_sec,           # 8
        in_out_ratio,              # 9
        fluctuation,               # 10
        syn_only_count,            # 11
        http_count,                # 12
    ]


# Threat labelling
def assign_label(features):
    tcp          = features[3]
    udp          = features[4]
    icmp         = features[5]
    arp          = features[6]
    unique_ports = features[7]
    pps          = features[8]
    syn_only     = features[11]
    http_count   = features[12]

    label = 0  # Normal

    # Label 1 — Port Scan: many distinct destination ports probed
    if unique_ports > 10 and pps > 20:
        label = max(label, 1)

    # Label 2 — UDP Flood: high UDP volume
    if udp > 10 and pps > 20:
        label = max(label, 2)

    # Label 3 — ICMP Flood: high ICMP volume
    if icmp > 20 and pps > 30:
        label = max(label, 3)

    # Label 4 — ARP Anomaly / Spoofing flood
    if arp > 5 and pps > 10:
        label = max(label, 4)

    # Label 5 — SYN Flood: many half-open connections (SYN without ACK)
    if syn_only > 10 and unique_ports <= 10 and pps > 30:
        label = max(label, 5)

    # Label 6 — HTTP Flood / Application-layer flood:
    #   High TCP count AND many connections to web ports AND high pps
    if http_count > 20 and tcp > 20 and pps > 30:
        label = max(label, 6)

    return label

WHITELIST = {"127.0.0.1", "192.168.100.1", options.ip} | set(options.whitelist)  # Allowed IPs
print(f"Trusted IPs: {WHITELIST}")

blocked_ips = {}  # Blacklisted IPs

# Records the blacklisted IPs and the justification for the block
def log_block(src_ip, label_name):
    with open("blocked_ips.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(), src_ip, label_name])

# Unblocks blacklisted IPs
def unblock_ip(src_ip):
    subprocess.run(
        ["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"],
        check=False
    )
    blocked_ips.pop(src_ip, None)
    print(f"[Firewall] Unblocked {src_ip}")

# Blocks IPs considered to be a threat to reduce the scale of the attck
# Temporary block to check if the attck persists or to check if a legitimate host was blocked
def block_ip(src_ip, reason, block_duration=60):
    if src_ip in WHITELIST or src_ip in blocked_ips:
        return
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"],
            check=True
        )
        blocked_ips[src_ip] = time.time()
        log_block(src_ip, reason)
        print(f"[Firewall] Blocked {src_ip} for {block_duration}s — {reason}")
        timer = threading.Timer(block_duration, unblock_ip, args=[src_ip])
        timer.daemon = True
        timer.start()
    except subprocess.CalledProcessError as e:
        print(f"[Firewall] Failed to block {src_ip}: {e}")

def alert(src_ip, label, features):
    # Print a live alert to stdout when a threat is detected.
    if label == 0:
        return
    name = LABEL_NAMES.get(label, "Unknown")
    print(f"\n  *** THREAT DETECTED ***")
    print(f"     Source IP : {src_ip}")
    print(f"     Attack    : [{label}] {name}")
    print(f"     Pkt/s     : {features[8]:.1f}  |  Pkts: {features[0]}  |  Bytes: {features[1]}")
    print(f"     TCP={features[3]}  UDP={features[4]}  ICMP={features[5]}  "
          f"ARP={features[6]}  SYN-only={features[11]}  HTTP={features[12]}")
    print(f"     Unique dst ports: {features[7]}  |  In/Out ratio: {features[9]:.2f}  "
          f"|  Fluctuation: {features[10]:.6f}\n")
    block_ip(src_ip, name)

# Window update & flush
def update_window(src_ip, packet_len, protocol, src_port, dst_port,
                  src_mac, direction, now, is_syn_only=False, is_http=False):
    global windows

    # Ensures that the blocked IP can't send any traffic
    if src_ip in blocked_ips:
    	print(f"[Firewall] Dropped packet from blocked IP: {src_ip}")
    	return

    if src_ip not in windows:
        windows[src_ip] = new_window(now)

    window = windows[src_ip]

    # Updates byte and packet counters
    window["packet_count"] += 1
    window["byte_count"]   += packet_len

    # Calculate current pps mid-window
    elapsed = now - window["start_time"]

    # Checks threshold mid window
    if elapsed < 0.2:
    	current_pps = 0
    else:
    	current_pps = window["packet_count"] / elapsed
    
    current_pps = window["packet_count"] / elapsed if elapsed > 0 else 0
    
    if current_pps > RATE_LIMIT_PPS or window["packet_count"] > RATE_LIMIT_PACKETS:
    	print(f"[RateLimit] {src_ip} exceeded limit - "
    	      f"{current_pps:.1f} pps / {window['packet_count']} pkts")
    	block_ip(src_ip, "Rate Limit Exceeded!") # Discards the window immediately
    	del windows[src_ip] # Stops processing this packet further
    	return

    # Protocol counts
    if protocol and protocol in window["protocol_count"]:
        window["protocol_count"][protocol] += 1

    # Direction
    if direction == "in":
        window["inbound_count"]  += 1
    else:
        window["outbound_count"] += 1

    # Ports
    if src_port is not None:
        window["src_ports"].add(src_port)
    if dst_port is not None:
        window["dst_ports"].add(dst_port)

    # MAC
    if src_mac:
        window["mac_addresses"].add(src_mac)

    # Timing (for Fluctuation)
    window["timestamps"].append(now)

    # Attack-specific counters
    if is_syn_only:
        window["syn_only_count"] += 1
    if is_http:
        window["http_count"] += 1

    # Flush window when its time slice has elapsed
    if now - window["start_time"] >= WINDOW_LENGTH:
        features = extract_features(window, now)
        label    = assign_label(features)
        row      = features + [label]
        feature_rows.append(row)

        # Print alert for any detected threat
        alert(src_ip, label, features)

        print(f"[Window] {src_ip} | pkts={features[0]} pps={features[8]:.1f} "
              f"label={label} ({LABEL_NAMES[label]})")

        del windows[src_ip]

def log_rate_limit(src_ip, pps, packet_count):
	filename = "rate_limit.csv"
	# Write header if the file doesn't exist yet
	write_header = not os.path.exists(filename)
	with open(filename, "a", newline="") as f:
		writer = csv.writer(f)
		if write_header:
			writer.writerow(["timestamp", "src_ip", "pps", "packet_count"])
		writer.writerow([datetime.now().isoformat(), src_ip, f"{pps:.1f}", packet_count])

# Packet callback (scapy)
def packet_processing(pkt):
    # Records the time of the packet being received
    now = time.time()

    # IP / transport layer
    if pkt.haslayer(IP):
        src_ip     = pkt[IP].src
        dst_ip     = pkt[IP].dst
        packet_len = len(pkt)
        protocol   = None
        src_port   = None
        dst_port   = None
        is_syn_only = False
        is_http     = False

        # Checks for TCP
        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # SYN flood detection:
            # TCP flags byte: SYN=0x02, ACK=0x10
            # Pure SYN (no ACK) means flags & 0x12 == 0x02
            tcp_flags = int(pkt[TCP].flags)
            if (tcp_flags & 0x12) == 0x02:
                is_syn_only = True

            # HTTP flood detection: targeting common web ports
            if dst_port in (80, 443, 8080, 8443):
                is_http = True

        # Checks for UDP
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # Checks for ICMP
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        src_mac   = pkt.src if hasattr(pkt, "src") else None
        # Checks if the packet is inbound or outbound
        direction = "in" if (local_ip and dst_ip == local_ip) else "out"

        try:
            # Stores packet features
            update_window(
                src_ip      = src_ip,
                packet_len  = packet_len,
                protocol    = protocol,
                src_port    = src_port,
                dst_port    = dst_port,
                src_mac     = src_mac,
                direction   = direction,
                now         = now,
                is_syn_only = is_syn_only,
                is_http     = is_http,
            )
        except Exception:
            traceback.print_exc()

    # ARP layer
    elif pkt.haslayer(ARP):
        try:
            src_ip     = pkt[ARP].psrc
            dst_ip     = pkt[ARP].pdst
            packet_len = len(pkt)
            src_mac    = pkt[ARP].hwsrc
            direction  = "in" if (local_ip and dst_ip == local_ip) else "out"

            update_window(
                src_ip     = src_ip,
                packet_len = packet_len,
                protocol   = "ARP",
                src_port   = None,
                dst_port   = None,
                src_mac    = src_mac,
                direction  = direction,
                now        = now,
            )
        except Exception:
            traceback.print_exc()

# Features for CSV export
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
    "syn_only_count",
    "http_count",
    "label",
]

def csv_dataset(filename):
    global windows, feature_rows

    print("\n[*] Flushing remaining windows...")

    now = time.time()

    # Appends the features and their values to the CSV file
    for src_ip, window in list(windows.items()):
        features = extract_features(window, now)
        label    = assign_label(features)
        feature_rows.append(features + [label])

    print(f"[*] Writing {len(feature_rows)} rows to {filename} ...")

    # Writes the gathered data line by line for each row
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES)
        writer.writerows(feature_rows)
    # Verifies that the CSV file was saved with its file name
    print(f"[*] Dataset saved: {filename}")

def format_mac(addr: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in addr)

# Raw-packet helper classes for manual parsing
# This is kept for low-level packet inspection if needed
class RawPacket:
   # Manual IPv4 header parser
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('!BBHHHBBH4s4s', self.packet[0:20])
        self.version          = header[0] >> 4
        self.header_length    = (header[0] & 0xF) * 4
        self.type_of_service  = header[1]
        self.packet_length    = header[2]
        self.frag_id          = header[3]
        self.offset           = header[4]
        self.ttl              = header[5]
        self.protocol_number  = header[6]
        self.checksum         = header[7]
        self.source           = header[8]
        self.destination      = header[9]
        self.source_addr      = ipaddress.ip_address(self.source)
        self.destination_addr = ipaddress.ip_address(self.destination)
        self.payload          = data[self.header_length:]
        self.protocol_map     = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_number]
        except KeyError:
            self.protocol = str(self.protocol_number)

    def print_header_short(self):
        print(f'Protocol: {self.protocol} {self.source_addr} -> {self.destination_addr}')

    # Extracts packet payload
    def print_data(self):
        print('*' * 10 + 'ASCII START' + '*' * 10)
        for b in self.payload:
            print(chr(b) if b < 128 else '.', end='')
        print('\n' + '*' * 10 + 'ASCII END' + '*' * 10)


class RawUDP:
    #  Manual UDP header parser
    def __init__(self, data):
        self.source_port, self.destination_port, self.length, self.checksum = \
            struct.unpack('!HHHH', data[:8])
        self.data = data[8:]


class RawARP:
    # Manual ARP header parser
    def __init__(self, data):
        (self.htype, self.ptype, self.hlen, self.plen, self.op,
         self.src_mac, self.src_ip, self.dst_mac, self.dst_ip) = \
            struct.unpack('!HHBBH6s4s6s4s', data[:28])
        self.src_ip = socket.inet_ntoa(self.src_ip)
        self.dst_ip = socket.inet_ntoa(self.dst_ip)

    def print_summary(self):
        op = "REQUEST" if self.op == 1 else "REPLY"
        print(f"ARP {op}: {self.src_ip} -> {self.dst_ip}")


class RawEthernet:
    # Manual Ethernet frame parser.
    def __init__(self, data):
        dst, src, proto = struct.unpack('!6s6sH', data[:14])
        self.src_mac = format_mac(src)
        self.dst_mac = format_mac(dst)
        self.proto   = socket.ntohs(proto)
        self.payload = data[14:]


def inspection(target_host):
    # Message for system start up
    print(f'[*] Packet sniffer started  |  monitoring IP: {target_host or "all"}')
    print(f'[*] Window length : {WINDOW_LENGTH}s')
    print(f'[*] Output file   : {options.out}')
    print( '[*] Press Ctrl+C to stop and export dataset.\n')
    print(f'[*] Detecting: {", ".join(LABEL_NAMES.values())}\n')

    # Listens for incoming data from all conncted hosts and ports
    try:
        print(f"Listening on: {get_if_list()}")
        sniff(prn=packet_processing, store=False, iface=get_if_list(), promisc=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")
    finally:
        csv_dataset(options.out)
        print("[*] Done.")
        sys.exit(0)


if __name__ == '__main__':
    inspection(options.ip)
