from scapy.all import *
import time

target = "192.168.100.3"

send(IP(dst=target)/TCP(dport=9999, flags="S"), count=20, inter=0.02)
