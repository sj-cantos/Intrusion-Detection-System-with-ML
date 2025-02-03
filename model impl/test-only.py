from scapy.all import *
import pandas as pd

def extract_features(packet):
    features = {
        "src_ip": packet[IP].src if IP in packet else "N/A",
        "dst_ip": packet[IP].dst if IP in packet else "N/A",
        "protocol": packet.proto if IP in packet else "N/A",
        "length": len(packet)
    }
    return features

sniff(prn=lambda pkt: print(extract_features(pkt)), count=10)
