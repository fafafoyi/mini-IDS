import subprocess, sys, os

STEPS = [
    ("Generating synthetic labeled traffic", "generate_traffic.py"),
    ("Running signature-based (rule) IDS",   "signature_ids.py"),
    ("Running anomaly_based (ML) IDS",       "anomaly_ids.py"),
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