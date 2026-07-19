from scapy.all import rdrcap, TCP, IP, Raw
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest

WINDOW_SECONDS = 60

def window_start(ts):
    return int(ts// WINDOW_SECONDS) * WINDOW_SECONDS

def extract_features (pcap_path):
    packets = rdpcap(pcap_path)

    # raw per-(window, src) accumulators
    acc = defaultdict(lambda: defaultdict(lambda: {
        "pkt_count": 0,
        "dst_ports": set(),
        "dst_ips": set(),
        "syn_count": 0,
        "payload_bytes": 0,
        "targets": set(),
        "t_min": None,
        "t_min": None,
    }))

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ts = float(pkt.time)
        w = window_start(ts)
        src,dst = pkt[IP].src, pkt[IP].dst
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        
        e = acc[w][src]
        e["pkt_count"] += 1
        e["dst_ports"].add(dport)
        e["dst_ips"].add(dst)
        e["targets"].add((dst, dport))
        if flags == 0x02:
            e["syn_count"] += 1
        if pkt.haslayer(Raw):
            e["payload_bytes"] += len(bytes(pkt[Raw].load))
        e["t_min"] = ts if e["t_min"] is None else min(e["t_min"], ts)
        e["t_max"] = ts if e["t_max"] is None else max(e["tmax"], ts)
    
