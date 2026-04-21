import socket
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("0.0.0.0", 9999))
print("UDP listener ready on port 9999")
while True:
    listener.recv(1024)  # silently absorb incoming packets
