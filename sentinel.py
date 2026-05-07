import time
import os
import subprocess
import pickle
import sys
import re
import warnings
import pandas as pd
import numpy as np
from collections import defaultdict
from tensorflow.keras.models import load_model

# --- CONFIGURATION ---
SCAN_DURATION = 10  
TEMP_PCAP = 'buffer.pcap'
TEMP_CSV = 'buffer.csv'

# --- UNIVERSAL MODE SETTINGS ---
CALIBRATION_CYCLES = 12  # 2 minutes of baseline learning
OUTLIER_THRESHOLD = 3.0  # Flag devices 3x worse than network median
MIN_PACKETS = 2  # Lowered to catch quieter devices

# --- ATTACK SIGNATURE DETECTION (TUNED!) ---
PORT_SCAN_THRESHOLD = 20  # Alert if device hits 20+ unique ports (avoid streaming false positives)
SYN_FLOOD_THRESHOLD = 100  # Alert if 100+ SYN packets without replies
SMALL_PACKET_RATIO = 0.8   # Alert if 80%+ packets are tiny (<100 bytes)
LARGE_PACKET_THRESHOLD = 500  # Packets larger than this = likely streaming/download

# Suppress TensorFlow Logs
warnings.filterwarnings("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Global State
suspicion_meter = defaultdict(int)
device_history = defaultdict(list)
network_baseline = []
calibration_mode = True
calibration_counter = 0

def print_banner():
    print("\033[96m")
    print(r"""
   ______      __               ____  _   _____
  //____/_  __/ /_  ___  _____ / __ \/ | / /   |
 / /   / / / / __ \/ _ \/ ___// / / /  |/ / /| |
/ /___/ /_/ / /_/ /  __/ /   / /_/ / /|  / ___ |
\\___/\__, /_.___/\___/_/   /_____/_/ |_/_/  |_|
     /____/    >> ATTACK-AWARE SENTINEL <<
    """)
    print("\033[0m")

def get_interfaces():
    """Returns list of wireless interfaces from iwconfig"""
    try:
        result = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode('utf-8')
        interfaces = re.findall(r'^([a-zA-Z0-9]+)\s+IEEE', result, re.MULTILINE)
        return interfaces, result
    except subprocess.CalledProcessError:
        return [], ""

def force_monitor_mode(iface):
    """Brute-force method using native 'iw' commands if airmon-ng fails"""
    print(f" [init] 🔨 Brute-forcing Monitor Mode on {iface}...")
    try:
        subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True)
        subprocess.run(['iw', iface, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def initialize_hardware():
    """Detect and use any interface already in Monitor Mode. If not, enable monitor mode WITHOUT renaming."""
    print(" [init] Scanning hardware...")

    ifaces, iw_output = get_interfaces()

    # ✅ 1. If ANY interface is already in Monitor Mode, USE IT as-is
    for iface in ifaces:
        if re.search(f"{iface}.*?Mode:Monitor", iw_output, re.DOTALL):
            print(f" [init] ✅ Active Monitor Interface detected: {iface}")
            return iface

    # ✅ 2. If none found, pick first wireless interface
    if not ifaces:
        print(" [FATAL] No Wi-Fi Adapter detected.")
        sys.exit(1)

    target = ifaces[0]
    print(f" [init] 🔄 Targeting adapter: {target}")

    # ✅ 3. Kill possible conflicts
    subprocess.run(['rfkill', 'unblock', 'wifi'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ✅ 4. Enable Monitor Mode WITHOUT renaming (native iw method)
    print(f" [init] 🔨 Enabling monitor mode on {target}...")
    try:
        subprocess.run(['ip', 'link', 'set', target, 'down'], check=True)
        subprocess.run(['iw', target, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['ip', 'link', 'set', target, 'up'], check=True)
    except subprocess.CalledProcessError:
        print(" [FATAL] Failed to switch interface to Monitor Mode.")
        sys.exit(1)

    # ✅ 5. Re-detect and return same interface name (NO renaming)
    time.sleep(1)
    ifaces, iw_output = get_interfaces()
    for iface in ifaces:
        if iface == target and re.search(f"{iface}.*?Mode:Monitor", iw_output, re.DOTALL):
            print(f" [init] ✅ Monitor Mode Active: {iface}")
            return iface

    print(" [FATAL] Monitor Mode failed to activate.")
    sys.exit(1)


def load_brain():
    print(" [init] Loading Neural Network...", end='', flush=True)
    try:
        model = load_model('cyberdna_autoencoder.h5', compile=False)
        with open('scaler.pkl', 'rb') as f: 
            scaler = pickle.load(f)
        with open('model_metadata.pkl', 'rb') as f: 
            meta = pickle.load(f)
        
        print(" DONE.")
        print(f" [init] 🌍 UNIVERSAL MODE + ATTACK SIGNATURES")
        print(f" [init] 🔬 Calibration: {CALIBRATION_CYCLES} cycles")
        print(f" [init] 🎯 Detecting: Port Scans, SYN Floods, Small Packet Attacks")
        
        return model, scaler, meta
    except Exception as e:
        print(f"\n [FATAL] Brain missing: {e}")
        sys.exit(1)

def capture_traffic(interface):
    status = "CALIBRATING" if calibration_mode else "MONITORING"
    cycles_left = f"({CALIBRATION_CYCLES - calibration_counter} left)" if calibration_mode else ""
    print(f"\n [scan] {status} {cycles_left} on {interface} ({SCAN_DURATION}s)...", end='', flush=True)
    
    cmd = ['tshark', '-i', interface, '-a', f'duration:{SCAN_DURATION}', '-w', TEMP_PCAP]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(" DONE.")
        return True
    except:
        print("\n [ERROR] Capture crashed. Interface likely detached.")
        return False

def detect_attack_signatures(group):
    """
    Rule-based attack detection (complement to ML model)
    Returns: (is_attack, attack_type, confidence)
    """
    attacks = []
    
    # Extract ports if available
    dst_ports = group['tcp_dport'].dropna().astype(str)
    dst_ports = pd.concat([dst_ports, group['udp_dport'].dropna().astype(str)])
    unique_ports = dst_ports.nunique()
    
    # Extract TCP flags if available (convert to string first!)
    tcp_flags = group['tcp_flags'].dropna().astype(str)
    syn_count = tcp_flags.str.contains('0x0002|0x.*2$|SYN', case=False, na=False).sum()  # SYN flag
    
    # Packet size analysis
    small_packets = (group['len'] < 100).sum()
    large_packets = (group['len'] > LARGE_PACKET_THRESHOLD).sum()
    total_packets = len(group)
    small_ratio = small_packets / total_packets if total_packets > 0 else 0
    large_ratio = large_packets / total_packets if total_packets > 0 else 0
    
    avg_size = group['len'].mean()
    
    # If mostly large packets = streaming/download, NOT an attack!
    if large_ratio > 0.3:  # 30%+ large packets = legitimate traffic
        return False, None, 0
    
    # SIGNATURE 1: Port Scan Detection
    # Must have many unique ports AND small packets (not streaming)
    if unique_ports >= PORT_SCAN_THRESHOLD and total_packets > 20 and avg_size < 300:
        confidence = min(100, (unique_ports / PORT_SCAN_THRESHOLD) * 50)
        attacks.append(('PORT_SCAN', confidence))
    
    # SIGNATURE 2: SYN Flood Detection
    if syn_count >= SYN_FLOOD_THRESHOLD:
        confidence = min(100, (syn_count / SYN_FLOOD_THRESHOLD) * 60)
        attacks.append(('SYN_FLOOD', confidence))
    
    # SIGNATURE 3: Small Packet Attack (probes, ACK floods)
    # Only trigger if VERY high small packet ratio and not just occasional small packets
    if small_ratio >= SMALL_PACKET_RATIO and total_packets > 50:
        confidence = min(100, small_ratio * 70)
        attacks.append(('SMALL_PKT_ATTACK', confidence))
    
    # SIGNATURE 4: High Packet Rate Attack
    # Only if high rate + small packets (not streaming which has large packets)
    if total_packets > 150 and avg_size < 200:
        confidence = min(100, (total_packets / 150) * 40)
        attacks.append(('HIGH_RATE_ATTACK', confidence))
    
    if attacks:
        # Return highest confidence attack
        best_attack = max(attacks, key=lambda x: x[1])
        return True, best_attack[0], best_attack[1]
    
    return False, None, 0

def analyze(model, scaler, meta):
    global suspicion_meter, device_history, network_baseline, calibration_mode, calibration_counter
    
    if not os.path.exists(TEMP_PCAP): 
        return
    
    feature_names = meta['feature_names']

    # Extract MORE features including TCP flags and ports
    cmd = ['tshark', '-r', TEMP_PCAP, '-T', 'fields', '-E', 'separator=,', '-E', 'header=y', 
           '-e', 'frame.time_epoch', '-e', 'wlan.sa', '-e', 'frame.len',
           '-e', 'tcp.dstport', '-e', 'udp.dstport', '-e', 'tcp.flags']
    
    with open(TEMP_CSV, 'w') as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

    try: 
        df = pd.read_csv(TEMP_CSV)
    except: 
        return
    
    if df.empty: 
        return

    # Data Cleaning
    df.columns = ['ts', 'mac', 'len', 'tcp_dport', 'udp_dport', 'tcp_flags']
    df = df.dropna(subset=['mac'])
    df['len'] = pd.to_numeric(df['len'], errors='coerce').fillna(0)
    df['ts'] = pd.to_numeric(df['ts'], errors='coerce')

    grouped = df.groupby('mac')
    
    if calibration_mode:
        print(f" [calib] Learning baseline from {len(grouped)} devices...")
    else:
        print(f" [proc] Analyzing {len(grouped)} devices...")

    current_cycle_mse = []
    
    # ALWAYS increment calibration counter, even if no devices found
    if calibration_mode:
        calibration_counter += 1

    for mac, group in grouped:
        # Filter noise
        if len(group) < MIN_PACKETS: 
            continue
        
        # --- RULE-BASED ATTACK DETECTION (FIRST!) ---
        is_attack, attack_type, sig_confidence = detect_attack_signatures(group)
        
        # --- FEATURE ENGINEERING FOR ML MODEL ---
        group = group.sort_values('ts')
        iats = np.diff(group['ts'])
        
        features = {
            'Mean_IAT': np.mean(iats) if len(iats) > 0 else 0,
            'Packet_Size_Variance': group['len'].var() if len(group) > 1 else 0,
            'Mean_Flow_Duration': (group['ts'].max() - group['ts'].min()) if len(group) > 1 else 0,
        }
        
        genome = pd.DataFrame([features])
        
        for feat in feature_names:
            if feat not in genome.columns:
                genome[feat] = 0
        
        X = genome[feature_names].copy()
        
        for col in X.columns:
            if col in ['Mean_IAT', 'Packet_Size_Variance', 'Mean_Flow_Duration']:
                X[col] = np.log1p(X[col].clip(lower=0))
        
        # ML Model Prediction
        try:
            X_scaled = scaler.transform(X)
            recon = model.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - recon, 2))
        except Exception as e:
            continue
        
        device_history[mac].append(mse)
        if len(device_history[mac]) > 20:
            device_history[mac] = device_history[mac][-20:]
        
        current_cycle_mse.append(mse)
        
        # --- CALIBRATION MODE ---
        if calibration_mode:
            attack_label = f" ⚠️ {attack_type}" if is_attack else ""
            print(f"  📡 MAC:{mac} | MSE:{mse:.4f} | Pkts:{len(group)}{attack_label}")
            continue
        
        # --- DETECTION MODE ---
        if len(network_baseline) < 10:
            print(f"  ⏳ MAC:{mac} | Still learning... | MSE:{mse:.4f}")
            continue
        
        # Calculate network statistics
        network_median = np.median(network_baseline)
        mad = np.median(np.abs(np.array(network_baseline) - network_median))
        
        if mad > 0:
            modified_z = 0.6745 * (mse - network_median) / mad
        else:
            modified_z = 0
        
        device_median = np.median(device_history[mac])
        
        # ML-based anomaly detection
        is_outlier = modified_z > OUTLIER_THRESHOLD
        is_sudden_change = (mse > device_median * 5) if device_median > 0 else False
        
        raw_avg_len = group['len'].mean()
        
        # --- HYBRID THREAT SCORING (ML + SIGNATURES) ---
        if is_attack:
            # Signature detection overrides ML
            suspicion_meter[mac] += int(sig_confidence * 0.6)  # 60% weight on signature
        elif is_outlier or is_sudden_change:
            # Check if it's legitimate heavy traffic (streaming, downloads)
            if raw_avg_len > 500:  # Large average packet = streaming/download
                suspicion_meter[mac] = max(0, suspicion_meter[mac] - 10)  # Reduce suspicion
            elif modified_z > OUTLIER_THRESHOLD * 2:
                suspicion_meter[mac] += 40
            else:
                suspicion_meter[mac] += 20
        else:
            suspicion_meter[mac] = max(0, suspicion_meter[mac] - 10)
        
        suspicion_meter[mac] = max(0, min(100, suspicion_meter[mac]))
        threat_level = suspicion_meter[mac]
        
        deviation_percent = ((mse / network_median) - 1) * 100 if network_median > 0 else 0
        
        # --- DISPLAY WITH ATTACK TYPE ---
        debug_info = f"MSE:{mse:.4f} Z:{modified_z:.1f} Pkts:{len(group)} Avg:{raw_avg_len:.0f}B"
        
        if is_attack:
            attack_label = f" [{attack_type}]"
        else:
            attack_label = ""
        
        if threat_level >= 80 or is_attack:
            print(f"  \033[91m🚨 [ALARM] MAC:{mac}{attack_label} | THREAT:{threat_level}% | {debug_info}\033[0m")
        elif threat_level >= 30:
            print(f"  \033[93m⚠️  [WATCH] MAC:{mac} | THREAT:{threat_level}% | Dev:+{deviation_percent:.0f}% | {debug_info}\033[0m")
        else:
            print(f"  \033[92m✅ [SAFE]  MAC:{mac} | THREAT:{threat_level}% | {debug_info}\033[0m")
    
    # Update baseline
    if current_cycle_mse:
        network_baseline.extend(current_cycle_mse)
        if len(network_baseline) > 200:
            network_baseline = network_baseline[-200:]
    
    # Calibration progress - check AFTER processing all devices
    if calibration_mode and calibration_counter >= CALIBRATION_CYCLES:
        calibration_mode = False
        print("\n" + "="*70)
        print("🎯 CALIBRATION COMPLETE! Now detecting attacks...")
        print("="*70)

    # Clean up
    if os.path.exists(TEMP_PCAP): 
        os.remove(TEMP_PCAP)
    if os.path.exists(TEMP_CSV):
        os.remove(TEMP_CSV)

if __name__ == '__main__':
    print_banner()
    
    model, scaler, meta = load_brain()
    active_interface = initialize_hardware()
    
    print("\n" + "="*70)
    print("🌍 HYBRID DETECTION MODE")
    print("   • ML Model: Detects anomalies via reconstruction error")
    print("   • Signatures: Detects port scans, SYN floods, DoS attacks")
    print("   • First 2 min: Learning network baseline")
    print("="*70 + "\n")
    
    while True:
        success = capture_traffic(active_interface)
        
        if success:
            analyze(model, scaler, meta)
        else:
            print(" [warn] Resurrecting interface...")
            subprocess.run(['pkill', 'tshark'], stdout=subprocess.DEVNULL)
            active_interface = initialize_hardware()
            time.sleep(2)
