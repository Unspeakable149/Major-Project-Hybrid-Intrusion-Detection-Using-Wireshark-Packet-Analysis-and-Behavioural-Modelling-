import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import joblib
import warnings

warnings.filterwarnings("ignore")

print("1. Loading the Super-Dataset...")
df = pd.read_csv("ai_ready_advanced_flows.csv")

print("2. Isolating Behavioral Features...")
# We must drop the "Source IP" column. 
# Why? Because an IP address is just a name, not a behavior. We want the AI to learn HOW hackers act, not memorize their names.
features = df.drop(columns=['Source IP'])

# Final safety net: ensure no infinite numbers or NaNs made it through
features = features.replace([float('inf'), float('-inf')], 0).fillna(0)

print("3. Scaling the Data Matrix...")
# Standardizing the data so massive numbers (like 40,000 bytes) don't overshadow tiny numbers (like a 0.5 syn_ack_ratio)
scaler = StandardScaler()
scaled_features = scaler.fit_transform(features)

print("4. Training the Advanced Deep-Learning K-Means Engine...")
# We are still looking for our 3 main clusters: Baseline, Moderate (Scans), Severe (DDoS)
ai_model = KMeans(n_clusters=3, random_state=42, n_init=10)
df['Cluster_Label'] = ai_model.fit_predict(scaled_features)

print("5. Saving the Advanced AI Brain...")
# Save these as NEW files so we don't overwrite your old ones just yet
joblib.dump(ai_model, "advanced_kmeans_model.pkl")
joblib.dump(scaler, "advanced_data_scaler.pkl")

print("\n=======================================================")
print("✅ SUCCESS! Phase 3: Advanced AI Training Complete.")
print("=======================================================")
print(f"Total Network Flows Analyzed: {len(df)}")
print("Your new AI Brain has been saved as 'advanced_kmeans_model.pkl'")