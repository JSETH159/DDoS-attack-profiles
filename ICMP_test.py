from scapy.all import *
import time

target = "192.168.100.3"

for _ in range(2):
    # ICMP
    send(IP(dst=target)/ICMP(), count=20, inter=0.01)
