import joblib
import pandas as pd
import pyshark
import time
import json
import pickle
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

# --- 1. LOAD THE MULTI-CLASS MODEL, ENCODER, AND FEATURES ---
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

# --- 2. CAPTURE AND PROCESS LIVE TRAFFIC (REAL-TIME) ---
def process_live_traffic():
    print("\nStarting live traffic capture for 15 seconds...")
    print("Please generate some network traffic now (e.g., open a website)...")
    
    YOUR_INTERFACE = 'Wi-Fi' 
    capture_duration = 15  # 15 seconds
    
    capture = None
    packet_lengths = []
    first_packet = None
    start_time = time.time() # Get the start time

    try:
        capture = pyshark.LiveCapture(interface=YOUR_INTERFACE)
        
        for packet in capture.sniff_continuously():
            if first_packet is None:
                first_packet = packet
            packet_lengths.append(float(packet.length))
            if time.time() - start_time > capture_duration:
                break 
        
        print("\nCapture complete.")

    except Exception as e:
        print(f"\n--- ERROR ---")
        print(f"An error occurred during capture: {e}")
        return
        
    finally:
        if capture:
            capture.close()
        print("Capture process has been closed.")

    print(f"Processed {len(packet_lengths)} packets.")
    
    if len(packet_lengths) < 2:
        print("Not enough packets captured to analyze a flow. Please try again.")
        return

    # --- 3. EFFICIENT FEATURE CALCULATION ---
    print("Calculating features...")
    
    live_data = {feature: 0.0 for feature in MODEL_FEATURE_NAMES}
    
    if 'Max Packet Length' in MODEL_FEATURE_NAMES:
        live_data['Max Packet Length'] = max(packet_lengths)
    if 'Packet Length Variance' in MODEL_FEATURE_NAMES:
        live_data['Packet Length Variance'] = pd.Series(packet_lengths).var()
    if 'Average Packet Size' in MODEL_FEATURE_NAMES:
        live_data['Average Packet Size'] = sum(packet_lengths) / len(packet_lengths)
    if 'Subflow Fwd Bytes' in MODEL_FEATURE_NAMES:
        live_data['Subflow Fwd Bytes'] = sum(packet_lengths)
    if 'Total Length of Fwd Packets' in MODEL_FEATURE_NAMES:
         live_data['Total Length of Fwd Packets'] = sum(packet_lengths)
    if 'Destination Port' in MODEL_FEATURE_NAMES and first_packet and hasattr(first_packet, 'tcp'):
        live_data['Destination Port'] = float(first_packet.tcp.dstport)

    # --- 4. MAKE A PREDICTION & TRANSLATE IT ---
    print("Making prediction...")
    live_df = pd.DataFrame([live_data], columns=MODEL_FEATURE_NAMES)
    live_df.fillna(0, inplace=True)
    
    # The model predicts a number (e.g., 0, 10, etc.)
    prediction_number = model.predict(live_df)
    
    # Use the encoder to translate the number back to a name
    prediction_name = encoder.inverse_transform(prediction_number)[0]
    
    print("\n--- AI MODEL PREDICTION ---")
    
    if prediction_name == "BENIGN":
        print(f"✅ Traffic Type Detected: {prediction_name}")
    else:
        # If it's any kind of attack
        print(f"🚨🚨🚨 ALERT: Attack Detected! 🚨🚨🚨")
        print(f"Attack Type: {prediction_name}")

# --- RUN THE MAIN FUNCTION ---
if __name__ == '__main__':
    process_live_traffic()