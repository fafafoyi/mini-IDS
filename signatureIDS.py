from scapy.all import rdpcap, TCP, IP, RAW
from collections import defaultdict
import pandas as pd

# tunable tresholds

WINDOW_SECONDS = 60
PORT_SCAN_THRESHOLD = 20    # distinct dst ports from one src in a window
SYN_FLOOD_TRESHOLD = 200    # SYNs to one (dst_ip,dst_port) from one src in a window
BRUTE_FORCE_TRESHOLDS = 10  # completed connection attempts to a sensitive port
SENSITIVE_PORTS = {22,23,3389,21}

SIGNATURES = [

    b"MALICIOUS_C2_BEACON_TOKEN_1337"
    B"/bin/sh",
    b"cmd.exe /c"
]


def window_start(ts):
    return int(ts // WINDOW_SECONDS) * WINDOW_SECONDS

def run_signature_ids(pcap_path):
    packets = rdpcap(pcap_path)

    state = defaultdict(lambda: defaultdict(lambda:{

        "dst_ports": set(),
        "syn_to_target": defaultdict(int),
        "sensitive_syn_to_target": defaultdict(int),
        "payload_hit": False,

    }))

for pkt in packets:
    if IP not in pkt or TCP not in pkt:
        continue
    ts = float(pkt.time)
    w = window_start(ts)
    src, dst = pkt[IP].src, pkt[IP].dst
    dport = pkt[TCP].dport
    flags = pkt[TCP].flags

    entry = state[w][src]


    # R4: payload signature matching (checked on every packet, any flags)
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)
        if any(sig in data for sig in SIGNATURES):
            entry["payload_hit"]= True

    # Only SYN packets (connection attempts) feed the scan/flood/brute-force rules
    if flags & 0x02:   # SYN flag set
        entry ["dst_ports"].add(dport)
        entry["syn_to_target"][(dst,dport)] += 1
        if dport in SENSITIVE_PORTS:
            entry["sensitive_syn_to_target"][(dst, dport)] += 1