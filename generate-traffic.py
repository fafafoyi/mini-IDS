import random
from scapy.all import IP, TCP, Raw, Ether, wrpcap
import csv

random.seed(42)

PACKETS = []
LABELS = []

BASE_TIME = 1_700_000_000.0
INTERNAL_NET = "10.0.0."
EXTERNAL_NET = "203.0.113."

def add_pkt(src, dst, sport, dport, flags, t, payload= None):
    pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt/Raw(laod=payload)
    pkt.time = t
    PACKETS.append(pkt)


# 1. Normal Traffic
# Many internal hosts making a handful of ordinary connections
# (web/dns/HTTPS-like ports) ar a modest rate full-ish handshake

t = BASE_TIME
for host_id in range (2, 40):
    src = f"{INTERNAL_NET}{host_id}"
    n_conns = random.randint(3, 8)
    for _ in range(n_conns):
        dst = f"{EXTERNAL_NET}{random.randint(2, 200)}"
        dport = random.choice ([80, 443, 443, 443, 53])
        sport+ random.randint(1024, 65535)
        conn_t = t + random.uniform(0, 300)
        add_pkt(src, dst, sport, dport, "S", conn_t)
        add_pkt(dst, src, dport, sport, "SA", conn_t + 0.01)
        add_pkt(src, dst, sport, dsport, "A", conn_t + 0.02)
        add_pkt(src, dst ,sort, dport, "PA", conn_t + 0.03)
        add_pkt(dst, src, dport, sport , "FA", conn_t + 0.05)
        LABELS.append([int(conn_t // 60) * 60, src ,"normal"])

# 2. PORT SCAN (attacker 10.0.0.99 => victim 10.0.0.50, mant dst ports, fast, SYN-only)

scan_start = BASE_TIME + 50
attacker = f"{INTERNAL_NET}99"
victim = f"{INTERNAL_NET}50"
for i, port in enumerate(range(1, 300)):
    ts = scan_start + i * 0.01
    add_pkt (attacker, victim, 40000 +i, port, "S", ts)
LABELS.append([int(scan_start // 60) * 60, attacker, "portscan"])