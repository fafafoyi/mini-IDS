
"""
main.py
--------
Runs the full Mini-IDS pipeline end to end:
  1. generate_traffic.py -> data/traffic.pcap + data/labels.csv
  2. signature_ids.py     -> data/signature_alerts.csv
  3. anomaly_ids.py        -> data/anomaly_alerts.csv
  4. evaluate.py           -> outputs/comparison.png + outputs/metrics_summary.csv
 
If you want to use REAL data instead of synthetic traffic (e.g. a CICIDS2017 pcap you
downloaded yourself), skip step 1: drop your own pcap at data/traffic.pcap
and your own ground-truth CSV (window_start,src_ip,label) at data/labels.csv,
then just run steps 2-4.
"""



import subprocess, sys, os

STEPS = [
    ("Generating synthetic labeled traffic", "generate_traffic.py"),
    ("Running signature-based (rule) IDS",   "signatureIDS.py"),
    ("Running anomaly_based (ML) IDS",       "anomalyIDS.py"),
    ("Evaluating & comparing detectors",    "evaluate.py"),
]

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    for title, script in STEPS:
        print(f"\n{"="*60}\n{title}\n{"="*60}")
        result = subprocess.run([sys.executable, os.path.join(here, script)])
        if result.returncode != 0:
            print(f"Step failed: {script}")
            sys.exit(1)
    print("\nPipeline complete. see outputs/comparison.png and outputs/metrics_summary.csv")