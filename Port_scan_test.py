from scapy.all import send, IP, TCP

def port_scan(target_ip, port_range=range(1, 200)):
    for port in port_range:
        send(
            IP(dst=target_ip) /
            TCP(dport=port, flags="S"),
            verbose=False
        )

port_scan("192.168.100.3")
