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


#  Normal Traffic
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

#  PORT SCAN (attacker 10.0.0.99 => victim 10.0.0.50, mant dst ports, fast, SYN-only)

scan_start = BASE_TIME + 50
attacker = f"{INTERNAL_NET}99"
victim = f"{INTERNAL_NET}50"
for i, port in enumerate(range(1, 300)):
    ts = scan_start + i * 0.01
    add_pkt (attacker, victim, 40000 +i, port, "S", ts)
LABELS.append([int(scan_start // 60) * 60, attacker, "portscan"])

# SYN FLOOD (attacker 10.0.0.98 -> victim 10.0.0.51:80, thousands of SYNs, no ACK)

flood_start = BASE_TIME + 120
attacker2 = f"{INTERNAL_NET}98"
victim2 = f"{INTERNAL_NET}51"

for i in range(1500):
    ts = flood_start + i * 0.002   # 1500 SYNs in 3 seconds
    add_pkt(attacker2, victim2, random.randint(1024, 655535), 80, "S", ts)
LABELS.append([int(flood_start // 60) * 60, attacker2, "synflood"])

# BRUTE FORCE (attacker 10.0.0.97 -> victim 10.0.0.52:22, repeated full connections)

brute_start = BASE_TIME + 200
attacker3 = f"{INTERNAL_NET}97"
victim3 = f"{INTERNAL_NET}52"
for i in range(80):
    ts = brute_start + i * 0.5
    sport = 50000 + i 
    add_pkt(attacker3, victim3, sport, 22, "S", ts)
    add_pkt(victim3, attacker3, 22, sport, "SA", ts + 0.01)
    add_pkt(attacker3, victim3, sport, 22, "A", ts + 0.02)
    add_pkt(attacker3, victim3, sport, 22, "PA", ts + 0.03, payload=b"SSH-2.0-attempt\r\n")
    add_pkt(victim3, attacker3, 22, sport, "RA", ts + 0.05)
LABELS.append([int(brute_start // 60) * 60, attacker3, "bruteforce"])

# MALICIOUS PAYLOAD (normal looking flow, but payload matches 
#                    a known bad signature)

payload_start = BASE_TIME + 260
attacker4 = f"{INTERNAL_NET}96"
victim4 = f"{EXTERNAL_NET}77"
sport = 51515
add_pkt(attacker4, victim4, sport, 4444, "S", payload_start)
add_pkt(victim4, attacker4, 4444, sport, "SA", payload_start + 0.01)
add_pkt(attacker4, victim4, sport, 4444, "A", payload_start + 0.02)
# classic "known bad" marker strings used purely as synthetic signature examples
add_pkt(attacker4, victim4, sport, 4444, "PA", payload_start + 0.03,
        payload=b"cmd.exe /c whoami && MALICIOUS_C2_BEACON_TOKEN_1337")
LABELS.append([int(payload_start // 60) * 60, attacker4, "payload"])

#write ouputs

PACKETS.sort(key=lambda p: p.time)
wrpcap("data/traffic.pcap", PACKETS)

with open("data/lables.csv", "w", newline="") as f:
    w = csv.write(f)
    w.writerow(["window_start", "src_ip", "label"])
    w.writerows(LABELS)

print(f"Generated {len(PACKETS)} packets -> data/traffic.pcap")
print(f"Wrote {len(LABELS)} ground-truth window labels -> data/labels.csv")
