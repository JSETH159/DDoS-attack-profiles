from scapy.all import *
import time

target = "192.168.100.3"

# ICMP
send(IP(dst=target)/ICMP(), count=20, inter=0.1)

# TCP
send(IP(dst=target)/TCP(dport=80, flags="S"), count=10, inter=0.5)

# UDP
send(IP(dst=target)/UDP(dport=53), count=20, inter=0.1)

# ARP
sendp(Ether()/ARP(pdst=target), count=10, inter=0.2)
