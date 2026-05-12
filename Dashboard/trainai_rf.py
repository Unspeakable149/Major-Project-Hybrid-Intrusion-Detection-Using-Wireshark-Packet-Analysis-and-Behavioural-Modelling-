import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import warnings

warnings.filterwarnings("ignore")

LABEL_NAMES = {0: "Baseline (Safe)", 1: "Moderate (Suspicious)", 2: "Severe (Critical Anomaly)"}

FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio'
]

def assign_behavioral_label(row):
    pps = row.get('packets_per_second', 0)
    sar = row.get('syn_ack_ratio', 0)
    ports = row.get('unique_target_ports', 0)
    avg_size = row.get('avg_packet_size', 0)

    if pps > 500 and sar > 5:
        return 2
    elif pps > 1000:
        return 2
    elif ports > 20:
        return 1
    elif pps > 300 and avg_size > 800:
        return 1
    elif pps <= 5 and avg_size < 150:
        return 0
    else:
        return 0


print("1. Loading Advanced Flow Dataset...")
df = pd.read_csv("ai_ready_advanced_flows.csv")
print(f"   Total flow records loaded: {len(df)}")

print("2. Isolating Behavioral Feature Matrix...")
features = df[FEATURE_COLS].replace([float('inf'), float('-inf')], 0).fillna(0)

print("3. Generating Supervised Labels via Behavioral Heuristics...")
labels = df.apply(assign_behavioral_label, axis=1)

label_dist = labels.value_counts().to_dict()
for label_id, count in sorted(label_dist.items()):
    print(f"   Class {label_id} ({LABEL_NAMES[label_id]}): {count} samples")

print("4. Scaling Feature Matrix with StandardScaler...")
scaler = StandardScaler()
scaled_features = scaler.fit_transform(features)

print("5. Partitioning Dataset (80% Train / 20% Test, Stratified)...")
try:
    X_train, X_test, y_train, y_test = train_test_split(
        scaled_features, labels, test_size=0.2, random_state=42, stratify=labels
    )
except ValueError:
    X_train, X_test, y_train, y_test = train_test_split(
        scaled_features, labels, test_size=0.2, random_state=42
    )

print(f"   Training set: {len(X_train)} samples")
print(f"   Test set:     {len(X_test)} samples")

print("6. Training Random Forest Classifier (100 estimators, balanced class weights)...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
rf_model.fit(X_train, y_train)

print("7. Evaluating Model Performance on Held-Out Test Set...")
y_pred = rf_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

present_classes = sorted(labels.unique())
present_names = [LABEL_NAMES[i] for i in present_classes]

print(f"\n   Overall Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
print("\n   Full Classification Report:")
print(classification_report(
    y_test, y_pred,
    labels=present_classes,
    target_names=present_names,
    zero_division=0
))

print("   Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred, labels=present_classes)
print(f"   Labels: {present_names}")
print(f"   {cm}")

print("\n8. Feature Importance Rankings (Descending):")
importance_df = pd.DataFrame({
    'Feature': FEATURE_COLS,
    'Importance': rf_model.feature_importances_
}).sort_values('Importance', ascending=False)

for _, row in importance_df.iterrows():
    bar_length = int(row['Importance'] * 60)
    bar = '#' * bar_length
    print(f"   {row['Feature']:30s}  {row['Importance']:.4f}  {bar}")

print("\n9. Serializing Model Artifacts...")
joblib.dump(rf_model, "rf_model.pkl")
joblib.dump(scaler, "rf_scaler.pkl")

print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)
print(f"  Training samples:  {len(X_train)}")
print(f"  Test samples:      {len(X_test)}")
print(f"  Final accuracy:    {accuracy * 100:.2f}%")
print(f"  Model artifact:    rf_model.pkl")
print(f"  Scaler artifact:   rf_scaler.pkl")
print("=" * 60)
