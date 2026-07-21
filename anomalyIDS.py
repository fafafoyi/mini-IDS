"""
anomaly_ids.py
---------------
A statistical / ML anomaly-based IDS. Unlike signature_ids.py (which knows
exactly what a port scan or a bad payload looks like), this detector has
NO built-in knowledge of attacks. It only learns "what normal looks like"
from a baseline of traffic and flags anything that deviates.
 
Step 1: Feature extraction (per src_ip, per time window same keying as
         signature_ids.py so results line up in evaluate.py):
    - pkt_count        : total packets sent by src in the window
    - pkt_rate         : packets / second
    - unique_dst_ports : distinct destination ports contacted (scan-like)
    - unique_dst_ips   : distinct destination hosts contacted (churn)
    - syn_ratio        : fraction of packets that are bare SYNs
                          (high => scanning/flooding, never completing)
    - avg_payload_len  : average payload size (very small avg => flood/scan
                          traffic that's mostly empty control packets)
    - conn_churn       : unique (dst_ip,dst_port) pairs / pkt_count
                          (near 1.0 => every packet opens a new target,
                           typical of scans; low => a few sustained flows)
 
Step 2: Model
    I used scikit-learn's IsolationForest, an unsupervised model that
    isolates points via random recursive splits, anomalies need fewer
    splits to isolate than normal points, so they get a high anomaly score.
    It is trained on ALL the extracted feature vectors (unsupervised: it
    never sees the labels), which mirrors real deployment where you don't
    have labeled attacks in production, only "mostly normal" traffic.
 
Step 3: Output
    A binary anomaly flag (-1 = anomaly / 1 = normal from sklearn. I remap
    to True/False) plus the anomaly score, per (window_start, src_ip), so
    it can be compared against the same ground truth as signature_ids.py.
"""



from scapy.all import rdpcap, TCP, IP, Raw
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
        "t_max": None,
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
        e["t_max"] = ts if e["t_max"] is None else max(e["t_max"], ts)
    
    rows = []
    for w, per_src in acc.items():
        for src, e in per_src.items():
            duration = max (e["t_max"] - e["t_min"], 0.001)
            rows.append({
                "window_start": w,
                "src_ip": src,
                "pkt_count": e["pkt_count"],
                "pkt_rate": e["pkt_count"] / duration,
                "unique_dst_ports": len(e["dst_ports"]),
                "unique_dst_ips": len(e["dst_ips"]),
                "syn_ratio": e["syn_count"] / e["pkt_count"],
                "avg_payload_len": e["payload_bytes"] / e["pkt_count"],
                "conn_churn": len(e["targets"]) / e["pkt_count"],
            })
    return pd.DataFrame(rows)

def run_anomaly_ids(pcap_path, contamination = 0.15):
    feats = extract_features(pcap_path)
    feature_cols = ["pkt_rate", "unique_dst_ports", "unique_dst_ips",
                    "syn_ratio", "avg_payload_len", "conn_churn"     ]
    X = feats[feature_cols].values



    model = IsolationForest(
        n_estimators = 200,
        contamination = contamination,
        random_state= 42,

    )
    model.fit(X)
    raw_pred = model.predict(X)    # 1 = normal, -1 = anomaly
    scores = model.decision_function(X)     #higher = more normal

    feats["anomaly_score"] = -scores     # flip so higher = more anomalous (nicer to read)
    feats["anom_prediction"] = (raw_pred == -1)
    return feats

if __name__ == "__main__":
    df = run_anomaly_ids("data/traffic.pcap")
    df.to_csv("data/anomaly_alerts.csv", index=False)
    print(f"Anomaly IDS flagged {df["anom_prediction"].sum()} / {len(df)} widnows as anomalous")
    print(df.sort_values("anomaly_score", ascending=False).head(10)[
    ["window_start", "src_ip", "pkt_rate", "unique_dst_ports", "syn_ratio",
     "conn_churn", "anomaly_score", "anom_prediction"]
])
    