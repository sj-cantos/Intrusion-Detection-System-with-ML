from scapy.all import *

target_ip = "192.168.1.1"
target_port = 80

for i in range(100):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(packet, verbose=False)
for i in range(100):
    packet = IP(dst=target_ip) / UDP(dport=53) / Raw(load="A"*100)
    send(packet, verbose=False)
