import pyshark
import time

YOUR_INTERFACE = 'Wi-Fi'

print("--- STARTING PROCESSING TEST ---")
print(f"Capturing on '{YOUR_INTERFACE}' for 5 seconds.")

try:
    capture = pyshark.LiveCapture(interface=YOUR_INTERFACE)
    capture.sniff(timeout=5)
    
    print("--- CAPTURE FINISHED ---")
    
    # This is the new test: Can we loop through the packets?
    print("Attempting to process each captured packet...")
    
    packet_count = 0
    for packet in capture: # This loop is where the old script fails
        packet_count += 1
        
    print(f"SUCCESS! Processed {packet_count} packets.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    print("--- TEST COMPLETE ---")