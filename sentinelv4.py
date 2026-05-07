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

# 🔥 BSSID FILTERING (Better for monitor mode!)
HOME_ROUTER_BSSID = "BE:7F:AE:05:4A:13"  # ⚠️ CHANGE THIS to your hotspot MAC!
HOME_NETWORK_SSID = "Rahul321"     # ⚠️ CHANGE THIS to your hotspot name!

# Optional: Whitelist known safe devices
KNOWN_SAFE_DEVICES = {
    # "11:22:33:44:55:66": "My Phone",
    # "77:88:99:aa:bb:cc": "My Laptop",
}

# --- DETECTION SETTINGS ---
MIN_PACKETS = 3
CALIBRATION_CYCLES = 3
ALARM_THRESHOLD_MULTIPLIER = 2.0
WATCH_THRESHOLD_MULTIPLIER = 1.5
LEGITIMACY_PACKET_SIZE = 800
VERBOSE_MODE = True

# --- ATTACK SIGNATURES ---
PORT_SCAN_THRESHOLD = 30
SMALL_PACKET_FLOOD_THRESHOLD = 100
SMALL_PACKET_RATIO = 0.85

# Suppress logs
warnings.filterwarnings("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Global state
device_baseline = defaultdict(list)
network_mse_history = []
calibration_mode = True
calibration_counter = 0
suspicion_meter = defaultdict(int)

def print_banner():
    print("\033[96m")
    print(r"""
   ______      __               ____  _   _____
  / ____/_  __/ /_  ___  _____ / __ \/ | / /   |
 / /   / / / / __ \/ _ \/ ___// / / /  |/ / /| |
/ /___/ /_/ / /_/ /  __/ /   / /_/ / /|  / ___ |
\____/\__, /_.___/\___/_/   /_____/_/ |_/_/  |_|
     /____/    >>POWERED BY RAHUL
    """)
    print("\033[0m")

def get_interfaces():
    try:
        result = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode('utf-8')
        interfaces = re.findall(r'^([a-zA-Z0-9]+)\s+IEEE', result, re.MULTILINE)
        return interfaces, result
    except subprocess.CalledProcessError:
        return [], ""

def initialize_hardware():
    print(" [init] Scanning hardware...")
    ifaces, iw_output = get_interfaces()
    
    for iface in ifaces:
        if re.search(f"{iface}.*?Mode:Monitor", iw_output, re.DOTALL):
            print(f" [init] ✅ Monitor interface: {iface}")
            return iface
    
    if not ifaces:
        print(" [FATAL] No Wi-Fi adapter found!")
        sys.exit(1)
    
    target = ifaces[0]
    print(f" [init] 🔄 Enabling monitor mode on {target}...")
    
    subprocess.run(['rfkill', 'unblock', 'wifi'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        subprocess.run(['ip', 'link', 'set', target, 'down'], check=True)
        subprocess.run(['iw', target, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['ip', 'link', 'set', target, 'up'], check=True)
    except subprocess.CalledProcessError:
        print(" [FATAL] Failed to enable monitor mode!")
        sys.exit(1)
    
    time.sleep(1)
    print(f" [init] ✅ Monitor mode active: {target}")
    return target

def load_brain():
    print(" [init] Loading model...", end='', flush=True)
    try:
        model = load_model('cyberdna_autoencoder.h5', compile=False)
        with open('scaler.pkl', 'rb') as f: 
            scaler = pickle.load(f)
        with open('model_metadata.pkl', 'rb') as f: 
            meta = pickle.load(f)
        
        print(" DONE.")
        print(f" [init] 📊 Features: {len(meta['feature_names'])}")
        print(f" [init] 🎯 Min packets: {MIN_PACKETS}")
        print(f" [init] 🔬 Calibration: {CALIBRATION_CYCLES} cycles")
        print(f" [init] 🏠 Home BSSID: {HOME_ROUTER_BSSID} ({HOME_NETWORK_SSID})")
        
        return model, scaler, meta
    except Exception as e:
        print(f"\n [FATAL] Model loading failed: {e}")
        sys.exit(1)

def capture_traffic(interface):
    status = "CALIBRATING" if calibration_mode else "MONITORING"
    cycles_left = f"({CALIBRATION_CYCLES - calibration_counter} left)" if calibration_mode else ""
    print(f"\n [scan] {status} {cycles_left} on {interface} ({SCAN_DURATION}s)...", end='', flush=True)
    
    # 🔥 BSSID FILTER: Only capture packets involving YOUR router!
    # This dramatically reduces captured data and protects privacy
    bssid_filter = f"wlan addr1 {HOME_ROUTER_BSSID} or wlan addr2 {HOME_ROUTER_BSSID} or wlan addr3 {HOME_ROUTER_BSSID}"
    
    cmd = ['tshark', '-i', interface, '-a', f'duration:{SCAN_DURATION}', 
           '-f', bssid_filter,  # 🔥 Apply BSSID filter during capture!
           '-w', TEMP_PCAP]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(" DONE.")
        return True
    except:
        print("\n [ERROR] Capture failed!")
        return False

def calculate_entropy(series):
    """Shannon entropy calculation"""
    series = series.dropna()
    if len(series) == 0:
        return 0.0
    value_counts = series.value_counts()
    probabilities = value_counts / len(series)
    return -np.sum(probabilities * np.log2(probabilities + 1e-10))

def detect_attack_signature(group):
    """Rule-based attack detection"""
    total_packets = len(group)
    
    if total_packets < 30:
        return False, None, 0
    
    dst_ports = pd.concat([
        group['tcp_dport'].dropna(),
        group['udp_dport'].dropna()
    ])
    unique_ports = dst_ports.nunique()
    
    small_packets = (group['len'] < 100).sum()
    large_packets = (group['len'] > LEGITIMACY_PACKET_SIZE).sum()
    small_ratio = small_packets / total_packets
    large_ratio = large_packets / total_packets
    avg_size = group['len'].mean()
    
    if large_ratio > 0.3:
        return False, None, 0
    
    if unique_ports >= PORT_SCAN_THRESHOLD and avg_size < 200:
        confidence = min(100, (unique_ports / PORT_SCAN_THRESHOLD) * 70)
        return True, 'PORT_SCAN', confidence
    
    if small_ratio >= SMALL_PACKET_RATIO and total_packets > SMALL_PACKET_FLOOD_THRESHOLD:
        confidence = min(100, small_ratio * 80)
        return True, 'SMALL_PKT_FLOOD', confidence
    
    return False, None, 0

def analyze(model, scaler, meta):
    global device_baseline, network_mse_history, calibration_mode, calibration_counter, suspicion_meter
    
    if not os.path.exists(TEMP_PCAP):
        return
    
    feature_names = meta['feature_names']
    
    # Extract features (no IP filtering needed - already filtered at capture!)
    cmd = ['tshark', '-r', TEMP_PCAP, '-T', 'fields', '-E', 'separator=,', '-E', 'header=y',
           '-e', 'frame.time_epoch', '-e', 'wlan.sa', '-e', 'frame.len',
           '-e', 'ip.dst', '-e', 'tcp.dstport', '-e', 'udp.dstport']
    
    with open(TEMP_CSV, 'w') as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)
    
    try:
        df = pd.read_csv(TEMP_CSV)
    except:
        return
    
    if df.empty:
        print(" [info] No traffic captured (hotspot might be idle)")
        return
    
    df.columns = ['ts', 'mac', 'len', 'dst_ip', 'tcp_dport', 'udp_dport']
    df = df.dropna(subset=['mac'])
    df['len'] = pd.to_numeric(df['len'], errors='coerce').fillna(0)
    df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
    
    grouped = df.groupby('mac')
    
    devices_total = len(grouped)
    devices_analyzed = sum(1 for _, g in grouped if len(g) >= MIN_PACKETS)
    devices_filtered = devices_total - devices_analyzed
    
    if calibration_mode:
        calibration_counter += 1
        print(f" [calib] Learning from {devices_total} devices ({devices_analyzed} analyzed, {devices_filtered} filtered)")
    else:
        print(f" [proc] Analyzing {devices_total} devices ({devices_analyzed} analyzed, {devices_filtered} filtered)")
    
    current_cycle_mse = []
    
    for mac, group in grouped:
        if len(group) < MIN_PACKETS:
            if VERBOSE_MODE and not calibration_mode:
                print(f"  \033[90m⊘  [SKIP]  MAC:{mac} | Too few packets: {len(group)}/{MIN_PACKETS}\033[0m")
            continue
        
        device_label = ""
        if mac in KNOWN_SAFE_DEVICES:
            device_label = f" ({KNOWN_SAFE_DEVICES[mac]})"
        
        is_attack, attack_type, sig_confidence = detect_attack_signature(group)
        
        group = group.sort_values('ts')
        iats = np.diff(group['ts'])
        all_ports = pd.concat([group['tcp_dport'], group['udp_dport']]).dropna()
        
        genome = {
            'Mean_RSSI': -65.0,
            'RSSI_Variance': 2.0,
            'Mean_Packet_Size': group['len'].mean(),
            'Packet_Size_Variance': group['len'].var() if len(group) > 1 else 0,
            'Mean_IAT': np.mean(iats) if len(iats) > 0 else 0,
            'Packet_Size_Entropy': calculate_entropy(group['len']),
            'Dst_IP_Entropy': calculate_entropy(group['dst_ip'].dropna()),
            'Port_Diversity': all_ports.nunique(),
            'ASN_Diversity': 1.0,
            'JA3_Diversity': 1.0
        }
        
        genome_df = pd.DataFrame([genome])
        
        for feat in feature_names:
            if feat not in genome_df.columns:
                if 'IAT' in feat:
                    genome_df[feat] = genome['Mean_IAT']
                elif 'Packet_Size' in feat or 'pkt_size' in feat:
                    genome_df[feat] = genome['Mean_Packet_Size']
                elif 'Variance' in feat:
                    genome_df[feat] = genome['Packet_Size_Variance']
                elif 'Port' in feat:
                    genome_df[feat] = genome['Port_Diversity']
                else:
                    genome_df[feat] = 0
        
        X = genome_df[feature_names].copy()
        
        for col in X.columns:
            if 'IAT' in col or 'Variance' in col or 'Duration' in col or 'size' in col:
                X[col] = np.log1p(X[col].clip(lower=0))
        
        try:
            X_scaled = scaler.transform(X)
            recon = model.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - recon, 2))
        except Exception as e:
            continue
        
        device_baseline[mac].append(mse)
        if len(device_baseline[mac]) > 50:
            device_baseline[mac] = device_baseline[mac][-50:]
        
        current_cycle_mse.append(mse)
        
        if calibration_mode:
            attack_label = f" [⚠️ {attack_type}]" if is_attack else ""
            print(f"  📡 MAC:{mac}{device_label} | MSE:{mse:.4f} | Pkts:{len(group)}{attack_label}")
            continue
        
        if len(network_mse_history) < 50:
            print(f"  ⏳ MAC:{mac}{device_label} | Still learning baseline...")
            continue
        
        network_median = np.median(network_mse_history)
        device_median = np.median(device_baseline[mac]) if len(device_baseline[mac]) > 5 else mse
        
        device_deviation = (mse / device_median) if device_median > 0.01 else 1.0
        network_deviation = (mse / network_median) if network_median > 0.01 else 1.0
        
        avg_packet_size = group['len'].mean()
        is_legitimate_heavy_traffic = avg_packet_size > LEGITIMACY_PACKET_SIZE
        
        if is_attack:
            threat_level = min(100, int(sig_confidence))
            status = "ALARM"
            label = f"[{attack_type}]"
        elif is_legitimate_heavy_traffic:
            threat_level = 0
            status = "SAFE"
            label = "[STREAMING]"
        elif device_deviation > ALARM_THRESHOLD_MULTIPLIER and network_deviation > ALARM_THRESHOLD_MULTIPLIER:
            threat_level = min(100, int(device_deviation * 15))
            status = "ALARM"
            label = "[ANOMALY]"
        elif device_deviation > WATCH_THRESHOLD_MULTIPLIER or network_deviation > WATCH_THRESHOLD_MULTIPLIER:
            threat_level = min(60, int(device_deviation * 10))
            status = "WATCH"
            label = ""
        else:
            threat_level = 0
            status = "SAFE"
            label = ""
        
        debug_info = f"MSE:{mse:.4f} DevMed:{device_median:.4f} NetMed:{network_median:.4f} Pkts:{len(group)} Avg:{avg_packet_size:.0f}B"
        
        if status == "ALARM":
            print(f"  \033[91m🚨 [ALARM] {label} MAC:{mac}{device_label} | THREAT:{threat_level}% | {debug_info}\033[0m")
        elif status == "WATCH":
            print(f"  \033[93m⚠️  [WATCH] MAC:{mac}{device_label} | THREAT:{threat_level}% | {debug_info}\033[0m")
        else:
            print(f"  \033[92m✅ [SAFE]  MAC:{mac}{device_label} | THREAT:{threat_level}% | {debug_info}\033[0m")
    
    if current_cycle_mse:
        network_mse_history.extend(current_cycle_mse)
        if len(network_mse_history) > 500:
            network_mse_history = network_mse_history[-500:]
    
    if calibration_mode and calibration_counter >= CALIBRATION_CYCLES:
        calibration_mode = False
        print("\n" + "="*70)
        print("🎯 CALIBRATION COMPLETE! Monitoring for threats...")
        print(f"📊 Network baseline: {len(network_mse_history)} MSE samples")
        print(f"📊 Median MSE: {np.median(network_mse_history):.4f}")
        print("="*70)
    
    if os.path.exists(TEMP_PCAP):
        os.remove(TEMP_PCAP)
    if os.path.exists(TEMP_CSV):
        os.remove(TEMP_CSV)

if __name__ == '__main__':
    print_banner()
    
    print("\n" + "="*70)
    print("🔧 SENTINEL v3.0 - BSSID-FILTERED:")
    print("   • BSSID filtering (WiFi layer privacy)")
    print("   • Only monitors YOUR network")
    print("   • Per-device baseline tracking")
    print("   • Attack signature detection")
    print(f"   • Home network: {HOME_NETWORK_SSID} ({HOME_ROUTER_BSSID})")
    print("="*70 + "\n")
    
    model, scaler, meta = load_brain()
    active_interface = initialize_hardware()
    
    while True:
        success = capture_traffic(active_interface)
        
        if success:
            analyze(model, scaler, meta)
        else:
            print(" [warn] Restarting interface...")
            subprocess.run(['pkill', 'tshark'], stdout=subprocess.DEVNULL)
            active_interface = initialize_hardware()
            time.sleep(2)
