import streamlit as st
import joblib
import pandas as pd
import pyshark
import time
import json
import pickle
import warnings
import os
# We no longer need asyncio

# Suppress warnings
warnings.filterwarnings('ignore')

# --- 1. LOAD MODELS (CACHED) ---
@st.cache_resource
def load_models():
    print("Loading models...")
    try:
        model = joblib.load('multi_class_model.joblib')
        with open('label_encoder.pkl', 'rb') as f:
            encoder = pickle.load(f)
        with open('top_20_features.json', 'r') as f:
            model_features = json.load(f)
        print("Models loaded successfully.")
        return model, encoder, model_features
    except FileNotFoundError:
        st.error("Error: Model or feature files not found in the folder.")
        return None, None, None

# --- 2. THE LIVE CAPTURE FUNCTION (NEW ROBUST METHOD) ---
def capture_and_predict(interface_name, features_list, model, encoder):
    
    # We no longer need any asyncio code.
    
    packet_lengths = []
    first_packet = None
    capture_duration = 15  # Capture for 15 seconds
    
    try:
        # Use a simple blocking capture
        capture = pyshark.LiveCapture(interface=interface_name)
        capture.sniff(timeout=capture_duration)
        
        # --- THIS IS THE KEY FIX ---
        # Instead of iterating `capture` (which causes a bug),
        # we directly access the internal `_packets` list.
        packet_list = [p for p in capture._packets]
        # --- END OF FIX ---

    except Exception as e:
        return f"Capture Error: {e}. Did you run as Administrator?"
    finally:
        # We still safely close the capture
        if 'capture' in locals():
            capture.close()
            
    if len(packet_list) < 2:
        return "Not enough packets captured to analyze."

    # --- Feature Calculation (using packet_list) ---
    first_packet = packet_list[0]
    for p in packet_list:
        packet_lengths.append(float(p.length))

    live_data = {feature: 0.0 for feature in features_list}
    
    if 'Max Packet Length' in features_list:
        live_data['Max Packet Length'] = max(packet_lengths)
    if 'Packet Length Variance' in features_list:
        live_data['Packet Length Variance'] = pd.Series(packet_lengths).var()
    if 'Average Packet Size' in features_list:
        live_data['Average Packet Size'] = sum(packet_lengths) / len(packet_lengths)
    if 'Subflow Fwd Bytes' in features_list:
        live_data['Subflow Fwd Bytes'] = sum(packet_lengths)
    if 'Total Length of Fwd Packets' in features_list:
         live_data['Total Length of Fwd Packets'] = sum(packet_lengths)
    if 'Destination Port' in features_list and first_packet and hasattr(first_packet, 'tcp'):
        live_data['Destination Port'] = float(first_packet.tcp.dstport)

    # --- Prediction ---
    live_df = pd.DataFrame([live_data], columns=features_list)
    live_df.fillna(0, inplace=True)
    
    prediction_number = model.predict(live_df)
    prediction_name = encoder.inverse_transform(prediction_number)[0]
    
    return prediction_name

# --- 3. BUILD THE STREAMLIT UI ---
st.title("My AI Network Security Dashboard 🛡️")
st.write("This tool uses a Machine Learning model to analyze live network traffic and detect potential threats.")

# Load the models
model, encoder, model_features = load_models()

if model:
    YOUR_INTERFACE = 'Wi-Fi' 
    st.write(f"Monitoring interface: **{YOUR_INTERFACE}**")

    if st.button("Start 15-Second Scan"):
        with st.spinner(f"Capturing traffic for 15 seconds..."):
            result = capture_and_predict(YOUR_INTERFACE, model_features, model, encoder)
        
        st.subheader("Scan Complete!")
        if "BENIGN" in result:
            st.success(f"✅ All clear! Traffic classified as: **{result}**")
        elif "Error" in result:
            st.error(f"❌ {result}")
        else:
            st.error(f"🚨🚨🚨 ALERT: Attack Detected! 🚨🚨🚨")
            st.error(f"Predicted Attack Type: **{result}**")

else:
    st.error("Dashboard cannot start. Model files are missing.")