import joblib
import pandas as pd
import json

# --- 1. LOAD THE MODEL AND FEATURES ---
print("Loading the saved AI model and feature list...")
try:
    model = joblib.load('lean_intrusion_model.joblib')
    with open('top_20_features.json', 'r') as f:
        MODEL_FEATURE_NAMES = json.load(f)
    print("Model and feature list loaded successfully.")
except FileNotFoundError:
    print("Error: Model or feature file not found.")
    exit()

# --- 2. USE REAL ATTACK DATA FROM THE TEST SET ---
print("\nUsing a REAL Port Scan attack data point from the test set...")

# This dictionary contains the features of a real attack from your test data
real_attack_data = {
    "Max Packet Length": 6.0,
    "Avg Bwd Segment Size": 6.0,
    "Packet Length Variance": 5.333333333,
    "Destination Port": 42510.0,
    "Packet Length Std": 2.309401077,
    "Average Packet Size": 5.0,
    "Bwd Packet Length Max": 6.0,
    "Bwd Packet Length Std": 0.0,
    "Bwd Packet Length Mean": 6.0,
    "Subflow Fwd Bytes": 2.0,
    "Total Length of Bwd Packets": 6.0,
    "Init_Win_bytes_forward": 1024.0,
    "Subflow Bwd Bytes": 6.0,
    "Total Length of Fwd Packets": 2.0,
    "Fwd Header Length.1": 24.0,
    "Packet Length Mean": 3.333333333,
    "Fwd Packet Length Max": 2.0,
    "Bwd Header Length": 20.0,
    "Avg Fwd Segment Size": 2.0,
    "Fwd Header Length": 24.0
}

# --- 3. MAKE A PREDICTION ---
print("Making prediction on the real attack data...")

attack_df = pd.DataFrame([real_attack_data], columns=MODEL_FEATURE_NAMES)
prediction = model.predict(attack_df)
probability = model.predict_proba(attack_df)

# --- 4. SHOW THE RESULT ---
print("\n--- AI MODEL PREDICTION ---")
if prediction[0] == 1:
    print(f"✅ SUCCESS! Model correctly identified the real attack as:")
    print(f"🚨🚨🚨 ALERT: MALICIOUS Traffic Detected! 🚨🚨🚨")
    print(f"Confidence (Malicious): {probability[0][1]*100:.2f}%")
else:
    print(f"❌ FAILURE: Model incorrectly classified the real attack as Benign.")
    print(f"Confidence (Benign): {probability[0][0]*100:.2f}%")