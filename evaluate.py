"""
evaluate.py
------------
Ties everything together:
  1. Loads ground truth labels (data/labels.csv) -> keyed by (window_start, src_ip)
  2. Loads signature IDS alerts and anomaly IDS alerts (same key)
  3. Reduces the multi-class ground truth to a BINARY task (attack vs normal)
     so both detectors, one multi-class-aware and one purely binary, can be
     compared fairly on the same footing.
  4. Computes confusion matrix, precision, recall, F1, and false positive
     rate for each detector.
  5. Also reports the signature IDS's per-attack-type accuracy, since unlike
     the anomaly detector it actually predicts *which* attack it thinks it saw.
  6. Saves a bar chart comparing the two detectors and prints a summary table.
"""


import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = "data"

labels = pd.read_csv(f"{DATA}/labels.csv")
sig = pd.read_csv(f"{DATA}/signature_alerts.csv")
anom = pd.read_csv(f"{DATA}/anomaly_alerts.csv")


# Build one ground-truth row per (window_start, src_ip). A src_ip can have
# generated several "normal" rows plus (for attackers) one attack row in the
# same window; if ANY row for that key is an attack, the key counts as attack.

def collapse_truth(row_group):
    labels_here = set(row_group)
    non_normal = labels_here - {"normal"}
    if non_normal:
        return sorted(non_normal)[0] # the attack label
    return "normal"

truth = (labels.groupby(["window_start", "src_ip"])["label"].apply(collapse_truth).reset_index())

truth["is_attack"] = truth["label"] != "normal"

# Merge each detector's predictions onto the full key space (all windows x
# src_ips that ANY source produced -- signature, anomaly, or truth) so that
# "no alert raised" correctly counts as a negative prediction.

all_keys = pd.concat([

    truth[["window_start", "src_ip"]],
    sig[["window_start", "src_ip"]],
    anom[["window_start", "src_ip"]],
]).drop_duplicates()

df = all_keys.merge(truth, on=["window_start", "src_ip"], how ="left")
df["is_attack"] = df["is_attack"].fillna(False)
df["label"] = df["label"].fillna("nromal")

df = df.merge(sig[["window_start", "src_ip", "sig_prediction"]],
        on =["window_start", "src_ip"], how="left")
df["sig_flag"] = df["sig_prediction"].notna()

df= df.merge(anom[["window_start", "src_ip", "anom_prediction"]],
    on=["window_start", "src_ip"], how = "left")
df["anom_flag"] = df["anom_prediction"].fillna(False)

y_true = df["is_attack"].astype(int)
y_sig = df["sig_flag"].astype(int)
y_anom = df["anom_flag"].astype(int)

def report(name, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    tn,fp,fn,tp = cm.ravel()
    precision = precision_score(y_true, y_pred, zero_division = 0)
    recall = recall_score(y_true, y_pred, zero_division = 0)
    f1 = f1_score(y_true, y_pred, zero_division = 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0 
    print(f"\n=== {name}===")
    print(f"confusion matrix [ [TN FP] [FN TP] ]:\n{cm}")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f} FalsePositiveRate={fpr:.3f}")
    return dict(name=name, tp=tp, fp=fp, fn=fn, tn=tn,
                precision=precision, recall=recall, f1=f1, fpr=fpr)

print(f"Total evaluation keys (widnow,src_ip pairs): {len(df)}")
print(f"Ground_truth attack keys: {int(y_true.sum())} / {len(df)}")

results = []
results.append(report("Signature-based IDS", y_sig))
results.append(report("Anomaly-based IDS (IsolationForest)", y_anom))

# Signature IDS attack-type accuracy (only it makes a typed prediction)

matched = df[df["sig_flag"] & df["is_attack"]]
correct_type =(matched["sig_prediction"] == matched["label"]).sum()
print(f"\nSignature IDS attack_TYPE accuracy on true positives: "
        f"{correct_type}/{len(matched)}"
        f"({(correct_type/len(matched)*100 if len(matched)else 0):.1f}%)"
)
print("\nWhich rule fired for each true attack (recall by attack class)")
for label_name in sorted(set(labels["label"])- {"normal"}):
    subset = df[df["label"] == label_name]
    caught_sig = subset["sig_flag"].sum()
    caught_anom = subset["anom_flag"].sum()
    print(f"   {label_name:12s}: total={len(subset):2d}"
        f"caught_by_signature={caught_sig}  caught_by_anomaly = {caught_anom}")

# Comparison chart

res_df = pd.DataFrame(results)
fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))

metrics = ["precision", "recall", "f1", "fpr"]
x= range(len(metrics))
width= 0.35
ax = axes[0]
ax.bar([i - width/2 for i in x], res_df.loc[0,metrics], width, label="Signature-based")
ax.bar([i + width/2 for i in x], res_df.loc[1, metrics], width, label="Anomaly-based")
ax.set_xticks(list(x))
ax.set_xticklabels(["Precision", "Recall", "F1", "False Pos. Rate"])
ax.set_ylim(0, 1.05)
ax.set_title("Detector comparison")
ax.legend()
ax.grid(axis="y", alpha=0.3)

ax2 = axes[1]
counts = res_df[["tp", "fp", "fn", "tn"]]
counts.index = res_df["name"]
counts.plot(kind="bar", stacked=False, ax=ax2, legend=True)
ax2.set_title("Raw counts (TP / FP / FN / TN)")
ax2.set_xticklabels(["Signature", "Anomaly"], rotation=0)
ax2.grid(axis ="y", alpha=0.3)

plt.tight_layout()
plt.savefig("outputs/comparison.png", dpi=140)
print("\nSaved comparison chart -> outputs/comparison.png")

res_df.to_csv("outputs/metrics_summary.csv", index=False)
print("Saved metrics table -> outputs/metrics_summary.csv")