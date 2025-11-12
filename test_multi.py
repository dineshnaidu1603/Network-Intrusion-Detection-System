import joblib
import pandas as pd
import json
import pickle
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

# --- 1. LOAD THE NEW MODEL, ENCODER, AND FEATURES ---
print("Loading the multi-class model, encoder, and feature list...")
try:
    model = joblib.load('multi_class_model.joblib')
    
    with open('label_encoder.pkl', 'rb') as f:
        encoder = pickle.load(f)
        
    with open('top_20_features.json', 'r') as f:
        MODEL_FEATURE_NAMES = json.load(f)
        
    print("All files loaded successfully.")
    
except FileNotFoundError:
    print("Error: Make sure 'multi_class_model.joblib', 'label_encoder.pkl',")
    print("and 'top_20_features.json' are in the same folder.")
    exit()

# --- 2. USE THE SAME REAL ATTACK DATA ---
print("\nUsing a REAL Port Scan attack data point from the test set...")

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

# --- 3. MAKE A PREDICTION & TRANSLATE IT ---
print("Making prediction on the real attack data...")

attack_df = pd.DataFrame([real_attack_data], columns=MODEL_FEATURE_NAMES)
attack_df.fillna(0, inplace=True) # Ensure no NaN values

# The model predicts a number (e.g., 10)
prediction_number = model.predict(attack_df)

# Use the encoder to translate the number back to a name
prediction_name = encoder.inverse_transform(prediction_number)

# --- 4. SHOW THE RESULT ---
print("\n--- AI MODEL PREDICTION ---")
print(f"Predicted Class: {prediction_name[0]}")

if prediction_name[0] == "PortScan":
    print(f"✅ SUCCESS! Model correctly identified the attack as {prediction_name[0]}")
else:
    print(f"❌ FAILURE: Model incorrectly classified the PortScan as {prediction_name[0]}")