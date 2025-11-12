import joblib
import pandas as pd
import pyshark
import time
import json
import warnings

# Suppress warnings for a cleaner output
warnings.filterwarnings('ignore')

# --- 1. LOAD THE TRAINED MODEL AND FEATURE NAMES ---
print("Loading the saved AI model and feature list...")
try:
    model = joblib.load('lean_intrusion_model.joblib')
    with open('top_20_features.json', 'r') as f:
        MODEL_FEATURE_NAMES = json.load(f)
    print("Model and feature list loaded successfully.")
    print(f"Model will use these {len(MODEL_FEATURE_NAMES)} features.")
except FileNotFoundError:
    print("Error: Model or feature file not found.")
    print("Please make sure 'lean_intrusion_model.joblib' and 'top_20_features.json' are in the same folder.")
    exit()

# --- 2. CAPTURE AND PROCESS LIVE TRAFFIC (FINAL ROBUST VERSION) ---
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
        # Use sniff_continuously() - this is the real-time, non-blocking method
        capture = pyshark.LiveCapture(interface=YOUR_INTERFACE)
        
        for packet in capture.sniff_continuously():
            # Process each packet as it arrives
            
            if first_packet is None:
                first_packet = packet
            
            packet_lengths.append(float(packet.length))

            # Check if 15 seconds have passed, then break the loop
            if time.time() - start_time > capture_duration:
                break 
        
        print("\nCapture complete.")

    except Exception as e:
        print(f"\n--- ERROR ---")
        print(f"An error occurred during capture: {e}")
        return
        
    finally:
        # Safely close the capture process
        if capture:
            capture.close()
        print("Capture process has been closed.")

    print(f"Processed {len(packet_lengths)} packets.")
    
    if len(packet_lengths) < 2:
        print("Not enough packets captured to analyze a flow. Please try again.")
        return

    # --- EFFICIENT FEATURE CALCULATION ---
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

    # --- 3. MAKE A PREDICTION ---
    print("Making prediction...")
    live_df = pd.DataFrame([live_data], columns=MODEL_FEATURE_NAMES)
    live_df.fillna(0, inplace=True)
    
    prediction = model.predict(live_df)
    probability = model.predict_proba(live_df)

    print("\n--- AI MODEL PREDICTION ---")
    if prediction[0] == 1:
        print(f"🚨🚨🚨 ALERT: MALICIOUS Traffic Detected! 🚨🚨🚨")
        print(f"Confidence (Malicious): {probability[0][1]*100:.2f}%")
    else:
        print(f"✅ Normal (Benign) Traffic Detected.")
        print(f"Confidence (Benign): {probability[0][0]*100:.2f}%")

# --- RUN THE MAIN FUNCTION ---
if __name__ == '__main__':
    process_live_traffic()