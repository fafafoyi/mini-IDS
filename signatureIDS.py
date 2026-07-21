"""
signature_ids.py
-----------------
A rule-based (signature) IDS. Reads a pcap, replays packets in time order,
and applies hand-written rules that mirror what Snort/Suricata rules do
conceptually (threshold-based rules + content matching), just implemented
directly in Python with scapy for transparency/teaching purposes.
 
Detection windowing:
  I bucketed time into fixed windows (default 60s) and key state per
  (src_ip) or (src_ip, dst_ip) inside that window, matching how the
  ground-truth labels in labels.csv are keyed. This keeps signature_ids.py
  and anomaly_ids.py directly comparable in evaluate.py.
 
Rules implemented:
  R1 PORT_SCAN   : a src_ip contacts >= PORT_SCAN_THRESHOLD distinct dst
                    ports (any dst_ip) within one window using SYN packets
                    that never complete a handshake back.
  R2 SYN_FLOOD    : a src_ip sends >= SYN_FLOOD_THRESHOLD SYN packets to a
                    single (dst_ip, dst_port) within one window.
  R3 BRUTE_FORCE  : a src_ip opens >= BRUTE_FORCE_THRESHOLD separate TCP
                    connections (each with its own SYN) to the same
                    (dst_ip, dst_port) on a sensitive port (22, 23, 3389, 21)
                    within one window.
  R4 PAYLOAD_MATCH: any packet whose payload contains a known bad-signature
                    byte string (analogous to a Snort "content:" rule).
 
Output: a DataFrame / CSV of alerts, one row per (window_start, src_ip),
with the highest-priority rule that fired, so it can be compared 1:1
against data/labels.csv in evaluate.py.
"""




from scapy.all import rdpcap, TCP, IP, Raw
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


    # evaluate rules per (windwo, src_ip) and emit alerts

    alerts = []
    for w, per_src in state.items():
        for src, e in per_src.items():
            fired = []


            if len (e["dst_ports"]) >= PORT_SCAN_THRESHOLD:
                fired.append(("portscan", len(e["dst_ports"])))


            max_syn_to_one_target = max(e["syn_to_target"].values(), default=0)
            if max_syn_to_one_target >= SYN_FLOOD_TRESHOLD:
                fired.append(("portscan", len(e["dst_ports"])))

            max_sensitive = max(e["sensitive_syn_to_target"].values(), default=0 )
            if max_sensitive >= BRUTE_FORCE_TRESHOLDS:
                fired.append(("bruteforce", max_sensitive))

            if e["payload_hit"]:
                fired.append(("payload", 1))
            
            if fired:
                #priority : worst/most spesific rule wins if several fire at once
                priority = {"payload": 4, "synflood":3, "portscan":2, "bruteforce":1}
                fired.sort(key=lambda x: priority[x[0]], reverse=True)
                alerts.append({
                    "window_start": w,
                    "src_ip": src,
                    "sig_prediction": fired[0][0],
                    "sig_evidence": fired[0][1],
                    "sig_all_rules_fired": ",".join(f[0]for f in fired),
                })
    return pd.DataFrame(alerts)

if __name__ == "__main__":
    df = run_signature_ids("data/traffic.pcap")
    df.to_csv("data/signature_alerts.csv", index=False)
    print(f"Signature IDS raised {len(df)} alerts")
    print(df["sig_prediction"].value_counts())