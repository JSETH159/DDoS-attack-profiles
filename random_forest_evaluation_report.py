import time
import psutil
import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay,
)

# Label map
LABEL_NAMES = {
    0: "Normal",
    1: "Port Scan",
    2: "UDP Flood",
    3: "ICMP Flood",
    4: "ARP Anomaly",
    5: "SYN Flood",
    6: "HTTP Flood",
}

# CPU monitoring helpers
def cpu_snapshot() -> float:
    # Return current process CPU % (averaged over a short interval).
    proc = psutil.Process(os.getpid())
    return proc.cpu_percent(interval=0.1)


def system_cpu() -> float:
    # Return system-wide CPU % across all cores.
    return psutil.cpu_percent(interval=0.1)


# Load data
print("=" * 60)
print("  Random Forest — Threat Detection Evaluation")
print("=" * 60)

df = pd.read_csv("traffic_patterns.csv")

print(f"\n[Data]  Rows: {len(df)}  |  Features: {df.shape[1] - 1}")
print(f"[Data]  Label distribution:\n{df['label'].value_counts().rename(LABEL_NAMES).to_string()}\n")

X = df.drop(columns=["label"])
y = df["label"]

# Train / test split  (70% training data & 30% unseen test data)
# Stratify preserves the class ratio in both splits
# This ensures that results are not biased by class imbalance in either subset.
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

print(f"[Split] Train: {len(X_train)} rows  |  Test (unseen): {len(X_test)} rows\n")

# Train — with CPU + wall-clock timing
rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,          # Use all CPU cores
    class_weight="balanced",   # Compensates for class imbalance
)

print("[Training] Starting…")
cpu_before_train   = cpu_snapshot()
sys_cpu_train_start = system_cpu()
t0_train           = time.perf_counter()

rf.fit(X_train, y_train)

train_wall_time  = time.perf_counter() - t0_train
cpu_after_train  = cpu_snapshot()
sys_cpu_train_end = system_cpu()

print(f"[Training] Done in {train_wall_time:.3f}s")
print(f"[CPU]      Process CPU during training : {cpu_after_train:.1f}%")
print(f"[CPU]      System  CPU during training : {sys_cpu_train_end:.1f}%\n")

# Inference on unseen test data — with CPU + timing
print("[Inference] Predicting on held-out test set…")
cpu_before_infer = cpu_snapshot()
t0_infer         = time.perf_counter()

y_pred = rf.predict(X_test)

infer_wall_time  = time.perf_counter() - t0_infer
cpu_after_infer  = cpu_snapshot()

print(f"[Inference] Done in {infer_wall_time:.6f}s  "
      f"({infer_wall_time / len(X_test) * 1000:.4f} ms per sample)")
print(f"[CPU]       Process CPU during inference : {cpu_after_infer:.1f}%\n")

# Core metrics on unseen test data
labels_present = sorted(y.unique())
label_names_present = [LABEL_NAMES[l] for l in labels_present]

accuracy  = accuracy_score(y_test, y_pred) * 100
precision = precision_score(y_test, y_pred, average="weighted", zero_division=0) * 100
recall    = recall_score(y_test, y_pred, average="weighted", zero_division=0) * 100
f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0) * 100

print("=" * 60)
print("  EVALUATION METRICS  (held-out test set)")
print("=" * 60)
print(f"  Accuracy   : {accuracy:.2f}%  — correctly identified out of all predictions")
print(f"  Precision  : {precision:.2f}%  — of flagged threats, how many were real")
print(f"  Recall     : {recall:.2f}%  — of real threats, how many were caught")
print(f"  F1-Score   : {f1:.2f}%  — harmonic mean of precision & recall")

# Per-class breakdown (false positive analysis included)
print("\n" + "=" * 60)
print("  PER-CLASS REPORT")
print("=" * 60)
report = classification_report(
    y_test, y_pred,
    labels=labels_present,
    target_names=label_names_present,
    zero_division=0,
    digits=4,
)
print(report)

# False positive / false negative breakdown per class
# A false positive for class C = model predicted C but true label != C
# A false negative for class C = true label is C but model predicted something else
print("=" * 60)
print("  FALSE POSITIVE & FALSE NEGATIVE BREAKDOWN")
print("=" * 60)
cm = confusion_matrix(y_test, y_pred, labels=labels_present)

fp_totals = {}
fn_totals = {}
for i, label in enumerate(labels_present):
    name = LABEL_NAMES[label]
    tp   = cm[i, i]
    fp   = cm[:, i].sum() - tp   # Other classes predicted as this class
    fn   = cm[i, :].sum() - tp   # This class predicted as other classes
    tn   = cm.sum() - tp - fp - fn
    fp_rate = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0.0
    fp_totals[name] = fp
    fn_totals[name] = fn
    print(f"  {name:<14}  TP={tp:>4}  FP={fp:>4}  FN={fn:>4}  TN={tn:>5}  "
          f"FP-rate={fp_rate:.2f}%")

print()

# Confusion matrix which is saved as a PNG
fig, ax = plt.subplots(figsize=(9, 7))
disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=label_names_present,
)
disp.plot(ax=ax, colorbar=True, cmap="Blues", xticks_rotation=45)
ax.set_title("Confusion Matrix — Held-out Test Set", fontsize=13, pad=14)
plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=150)
plt.close()
print("[Plot] Confusion matrix saved → confusion_matrix.png")

# Cross-validation on training data
# 5-fold stratified CV tests to show how the model generalises to different train/test splits
print("\n" + "=" * 60)
print("  CROSS-VALIDATION  (5-fold stratified, training data)")
print("=" * 60)

cpu_before_cv = cpu_snapshot()
t0_cv = time.perf_counter()

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = cross_validate(
    rf, X_train, y_train, cv=cv,
    scoring=["accuracy", "precision_weighted", "recall_weighted", "f1_weighted"],
    n_jobs=-1,
    return_train_score=False,
)

cv_wall_time  = time.perf_counter() - t0_cv
cpu_after_cv  = cpu_snapshot()

print(f"  CV completed in {cv_wall_time:.2f}s  |  CPU after CV: {cpu_after_cv:.1f}%\n")

cv_metrics = {
    "Accuracy":  cv_results["test_accuracy"],
    "Precision": cv_results["test_precision_weighted"],
    "Recall":    cv_results["test_recall_weighted"],
    "F1-Score":  cv_results["test_f1_weighted"],
}

# Formats metrics
for name, scores in cv_metrics.items():
    print(f"  {name:<12}  mean={scores.mean()*100:.2f}%   "
          f"std=±{scores.std()*100:.2f}%   "
          f"folds=[{', '.join(f'{s*100:.1f}' for s in scores)}]")

# Feature importance
print("\n" + "=" * 60)
print("  FEATURE IMPORTANCE  (mean decrease in impurity)")
print("=" * 60)
importance = pd.Series(
    rf.feature_importances_,
    index=X.columns,
).sort_values(ascending=False)

for feat, imp in importance.items():
    bar = "█" * int(imp * 200)
    print(f"  {feat:<22} {imp:.4f}  {bar}")

# Feature importance bar chart
fig2, ax2 = plt.subplots(figsize=(10, 5))
importance.plot(kind="bar", ax=ax2, color="steelblue", edgecolor="white")
ax2.set_title("Feature Importance", fontsize=13)
ax2.set_ylabel("Mean Decrease in Impurity")
ax2.set_xlabel("Feature")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig("feature_importance.png", dpi=150)
plt.close()
print("\n[Plot] Feature importance saved → feature_importance.png")

# CPU utilisation summary
print("\n" + "=" * 60)
print("  CPU UTILISATION SUMMARY")
print("=" * 60)
print(f"  Training   wall time : {train_wall_time:.3f}s")
print(f"  Inference  wall time : {infer_wall_time:.6f}s  "
      f"({infer_wall_time / len(X_test) * 1000:.4f} ms/sample)")
print(f"  CV         wall time : {cv_wall_time:.2f}s")
print(f"  CPU at end of run    : {cpu_snapshot():.1f}%  (process)")
print(f"  System CPU at end    : {system_cpu():.1f}%")
print(f"  CPU cores available  : {psutil.cpu_count(logical=True)}")
print(f"  RAM used by process  : {psutil.Process(os.getpid()).memory_info().rss / 1024**2:.1f} MB")

print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  Accuracy  on unseen data : {accuracy:.2f}%")
print(f"  F1-Score  on unseen data : {f1:.2f}%")
print(f"  CV mean accuracy         : {cv_metrics['Accuracy'].mean()*100:.2f}% "
      f"(±{cv_metrics['Accuracy'].std()*100:.2f}%)")
total_fp = sum(fp_totals.values())
total_fn = sum(fn_totals.values())
total_test = len(y_test)
print(f"  Total false positives    : {total_fp}  "
      f"({total_fp / total_test * 100:.2f}% of test samples misidentified)")
print(f"  Total false negatives    : {total_fn}  "
      f"({total_fn / total_test * 100:.2f}% of real threats missed)")
print("=" * 60)
print()
