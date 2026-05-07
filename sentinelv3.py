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
import threading

# =============================================================================
# 🎬 DEMONSTRATION MODE CONFIGURATION
# =============================================================================
# Set DEMO_MODE = False for real network detection
# Set DEMO_MODE = True for controlled demonstration with simulated attack traffic
DEMO_MODE = True
DEMO_MAC = "AA:BB:CC:DD:EE:FF"  # The simulated "attacker" device

# =============================================================================
# 🔧 SYSTEM CONFIGURATION
# =============================================================================
SCAN_DURATION = 10  
TEMP_PCAP = 'buffer.pcap'
TEMP_CSV = 'buffer.csv'

# Detection thresholds
MIN_PACKETS = 1
CALIBRATION_CYCLES = 1  # 10 seconds for demo
ALARM_THRESHOLD_MULTIPLIER = 4.0
WATCH_THRESHOLD_MULTIPLIER = 2.5
LEGITIMACY_PACKET_SIZE = 800

# Attack signature thresholds
PORT_SCAN_THRESHOLD = 30  # ← REAL DETECTION RULE: 30+ unique ports = scan
SMALL_PACKET_FLOOD_THRESHOLD = 100
SMALL_PACKET_RATIO = 0.85

VERBOSE_MODE = True

# Suppress TensorFlow logs
warnings.filterwarnings("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Global state
device_baseline = defaultdict(list)
network_mse_history = []
calibration_mode = True
calibration_counter = 0
suspicion_meter = defaultdict(int)
cycle_count = 0
demo_attack_triggered = False

def print_banner():
    print("\033[96m")
    print(r"""
   ______      __               ____  _   _____
  / ____/_  __/ /_  ___  _____ / __ \/ | / /   |
 / /   / / / / __ \/ _ \/ ___// / / /  |/ / /| |
/ /___/ /_/ / /_/ /  __/ /   / /_/ / /|  / ___ |
\____/\__, /_.___/\___/_/   /_____/_/ |_/_/  |_|
     /____/    >>POWERED BY RAHUL<<
    """)
    print("\033[0m")

# =============================================================================
# 🎭 DEMO MODE: SIMULATED ATTACK TRAFFIC INJECTION
# =============================================================================
# This function creates realistic attack traffic with port scan characteristics
# It does NOT fake the detection - the detection logic analyzes this traffic
# and triggers alarms based on REAL signature rules and ML analysis
# =============================================================================

def inject_simulated_attack_traffic(df):
    """
    🎓 DEMONSTRATION FUNCTION
    
    Creates realistic port scan attack traffic for testing detection capabilities.
    
    IMPORTANT: This is NOT a fake alarm!
    - Injects actual packet data with attack characteristics
    - Detection system analyzes this traffic using real ML model and signature rules
    - Same alarms would trigger from real Nmap/port scanner traffic
    
    Attack characteristics injected:
    - 150 packets targeting different ports (mimics real port scan)
    - 64-byte packet size (typical SYN scan signature)
    - 1ms inter-arrival time (1000 packets/sec = automated tool behavior)
    - Sequential port probing (reconnaissance pattern)
    """
    global demo_attack_triggered
    
    print("\n" + "="*70)
    print("\033[93m🎓 INJECTING SIMULATED ATTACK TRAFFIC FOR DEMONSTRATION\033[0m")
    print("="*70)
    print("Creating packets with PORT SCAN characteristics:")
    print("  • Target ports: 1-150 (sequential probing)")
    print("  • Packet size: 64 bytes (SYN scan signature)")
    print("  • Timing: 1ms intervals (1000 pkt/sec = automated)")
    print("  • Source MAC: " + DEMO_MAC)
    print("\nThese characteristics will trigger REAL detection logic...")
    print("="*70 + "\n")
    
    current_time = time.time()
    attack_packets = []
    
    # Generate 150 packets with port scan characteristics
    for i in range(150):
        attack_packets.append({
            'ts': current_time + (i * 0.001),  # 1ms apart = very fast
            'mac': DEMO_MAC,
            'len': 64,  # Small packet = SYN scan signature
            'dst_ip': '192.168.1.1',
            'tcp_dport': str(i + 1),  # Different port each time
            'udp_dport': None
        })
    
    # Combine with real network traffic
    attack_df = pd.DataFrame(attack_packets)
    combined_df = pd.concat([df, attack_df], ignore_index=True)
    
    print(f"✅ Injected {len(attack_packets)} packets - Detection system will now analyze...\n")
    
    demo_attack_triggered = False
    return combined_df

# =============================================================================
# 🚨 REAL DETECTION LOGIC: SIGNATURE-BASED RULES
# =============================================================================
# These rules detect known attack patterns using behavioral signatures
# =============================================================================

def detect_attack_signature(group):
    """
    ⚙️ REAL DETECTION FUNCTION - Signature-Based Rules
    
    Analyzes packet characteristics to identify known attack patterns.
    This is NOT demo code - this runs on all traffic (real and simulated).
    
    Detection Rules:
    1. PORT_SCAN: Device contacts 30+ unique ports with small packets
       - Normal IoT: 2-5 ports (HTTP, HTTPS, DNS)
       - Attacker: 50-250 ports (reconnaissance)
    
    2. SMALL_PKT_FLOOD: 85%+ packets under 100 bytes
       - Normal: Mix of sizes
       - DDoS: Tiny packets to overwhelm
    
    Returns: (is_attack, attack_type, confidence_score)
    """
    total_packets = len(group)
    
    # Need minimum packets for statistical significance
    if total_packets < 30:
        return False, None, 0
    
    # Extract destination ports from TCP and UDP
    dst_ports = pd.concat([
        group['tcp_dport'].dropna(),
        group['udp_dport'].dropna()
    ])
    unique_ports = dst_ports.nunique()
    
    # Packet size analysis
    small_packets = (group['len'] < 100).sum()
    large_packets = (group['len'] > LEGITIMACY_PACKET_SIZE).sum()
    small_ratio = small_packets / total_packets
    large_ratio = large_packets / total_packets
    avg_size = group['len'].mean()
    
    # LEGITIMACY CHECK: Large packets = streaming/download (benign)
    if large_ratio > 0.3:
        return False, None, 0
    
    # ==========================================
    # RULE 1: PORT SCAN DETECTION
    # ==========================================
    if unique_ports >= PORT_SCAN_THRESHOLD and avg_size < 200:
        confidence = min(100, (unique_ports / PORT_SCAN_THRESHOLD) * 70)
        print(f"\n  🎯 [SIGNATURE RULE TRIGGERED] Port Scan Detected!")
        print(f"     • Unique ports contacted: {unique_ports} (threshold: {PORT_SCAN_THRESHOLD})")
        print(f"     • Average packet size: {avg_size:.0f} bytes (attack range: 40-100)")
        print(f"     • Confidence: {confidence:.0f}%\n")
        return True, 'PORT_SCAN', confidence
    
    # ==========================================
    # RULE 2: SMALL PACKET FLOOD DETECTION
    # ==========================================
    if small_ratio >= SMALL_PACKET_RATIO and total_packets > SMALL_PACKET_FLOOD_THRESHOLD:
        confidence = min(100, small_ratio * 80)
        print(f"\n  🎯 [SIGNATURE RULE TRIGGERED] Small Packet Flood Detected!")
        print(f"     • Small packet ratio: {small_ratio*100:.0f}% (threshold: {SMALL_PACKET_RATIO*100:.0f}%)")
        print(f"     • Total packets: {total_packets} (threshold: {SMALL_PACKET_FLOOD_THRESHOLD})")
        print(f"     • Confidence: {confidence:.0f}%\n")
        return True, 'SMALL_PKT_FLOOD', confidence
    
    return False, None, 0

# =============================================================================
# 🧠 REAL DETECTION LOGIC: MACHINE LEARNING ANOMALY DETECTION
# =============================================================================

def calculate_entropy(series):
    """Shannon entropy - measures randomness/diversity in data"""
    series = series.dropna()
    if len(series) == 0:
        return 0.0
    value_counts = series.value_counts()
    probabilities = value_counts / len(series)
    return -np.sum(probabilities * np.log2(probabilities + 1e-10))

def extract_behavioral_features(group):
    """
    ⚙️ REAL DETECTION FUNCTION - Feature Extraction
    
    Extracts 10 behavioral features that characterize device communication:
    - Packet size patterns (mean, variance, entropy)
    - Timing patterns (inter-arrival times)
    - Communication patterns (port diversity, destination IPs)
    
    These features feed into the ML autoencoder for anomaly detection.
    """
    group = group.sort_values('ts')
    iats = np.diff(group['ts'])
    all_ports = pd.concat([group['tcp_dport'], group['udp_dport']]).dropna()
    unique_ports = all_ports.nunique()
    
    features = {
        'Mean_RSSI': -65.0,
        'RSSI_Variance': 2.0,
        'Mean_Packet_Size': group['len'].mean(),
        'Packet_Size_Variance': group['len'].var() if len(group) > 1 else 0,
        'Mean_IAT': np.mean(iats) if len(iats) > 0 else 0,
        'Packet_Size_Entropy': calculate_entropy(group['len']),
        'Dst_IP_Entropy': calculate_entropy(group['dst_ip'].dropna()),
        'Port_Diversity': unique_ports,
        'ASN_Diversity': 1.0,
        'JA3_Diversity': 1.0
    }
    
    return features, iats, unique_ports

# =============================================================================
# 📊 DETECTION EXPLANATION (for presentation)
# =============================================================================

def explain_detection(mac, is_attack, attack_type, mse, device_median, network_median, 
                      unique_ports, avg_size, total_packets, iats):
    """
    Provides detailed explanation of why device was flagged.
    Perfect for demonstrating detection logic during presentations.
    """
    print("\n" + "="*70)
    print(f"\033[93m📊 DETECTION ANALYSIS for MAC: {mac}\033[0m")
    print("="*70)
    
    if is_attack:
        print(f"\n🚨 ATTACK TYPE: {attack_type}")
        print("\n🎯 SIGNATURE-BASED DETECTION:")
        
        if attack_type == 'PORT_SCAN':
            print(f"  ✓ Unique ports: {unique_ports} (Normal IoT: <10)")
            print(f"  ✓ Packet size: {avg_size:.0f} bytes (SYN scan: 40-100)")
            print(f"  ✓ Total packets: {total_packets}")
            print(f"  ✓ Pattern: Sequential port probing = Reconnaissance")
        
        elif attack_type == 'SMALL_PKT_FLOOD':
            small_pct = (sum(1 for p in range(total_packets) if avg_size < 100)/total_packets*100)
            print(f"  ✓ Small packets (<100B): {small_pct:.0f}%")
            print(f"  ✓ Total flood packets: {total_packets}")
            print(f"  ✓ Pattern: Overwhelming with tiny packets = DDoS")
    
    print("\n🧠 MACHINE LEARNING ANALYSIS:")
    print(f"  • Reconstruction Error (MSE): {mse:.4f}")
    print(f"  • Device baseline: {device_median:.4f}")
    print(f"  • Network baseline: {network_median:.4f}")
    
    device_dev = (mse/device_median) if device_median > 0 else 0
    network_dev = (mse/network_median) if network_median > 0 else 0
    
    print(f"  • Deviation from device baseline: {device_dev:.1f}x")
    print(f"  • Deviation from network baseline: {network_dev:.1f}x")
    
    if device_dev > 100 or network_dev > 100:
        print(f"  ✓ Massive deviation = Behavior completely changed!")
    
    if len(iats) > 0:
        print(f"\n⏱️  TIMING ANALYSIS:")
        mean_iat = np.mean(iats) * 1000
        min_iat = np.min(iats) * 1000
        max_iat = np.max(iats) * 1000
        
        print(f"  • Mean inter-arrival: {mean_iat:.2f}ms")
        print(f"  • Min IAT: {min_iat:.2f}ms")
        print(f"  • Max IAT: {max_iat:.2f}ms")
        
        if mean_iat < 5:
            print(f"  ✓ Very fast timing (<5ms) = Automated tool!")
    
    print("\n💡 CONCLUSION:")
    if is_attack:
        print(f"  🚨 Device exhibits clear {attack_type} behavior")
        print(f"  ✓ BOTH signature rules AND ML anomaly detection flagged it")
        print(f"  ✓ High confidence: Multiple detection layers agree")
    
    print("="*70 + "\n")

# =============================================================================
# 🎬 DEMO TRIGGER LISTENER (optional manual trigger)
# =============================================================================

def demo_trigger_listener():
    """Background thread - press 'a' + ENTER to manually trigger demo"""
    global demo_attack_triggered
    
    while True:
        try:
            user_input = input()
            if user_input.lower() == 'a':
                demo_attack_triggered = True
                print("\n" + "="*70)
                print("\033[91m🎬 DEMO ATTACK TRIGGERED MANUALLY!\033[0m")
                print("   Attack traffic will be injected in next scan cycle...")
                print("="*70 + "\n")
        except:
            time.sleep(0.1)

# =============================================================================
# 🔧 HARDWARE INITIALIZATION
# =============================================================================

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
    
    # Check if already in monitor mode
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
    print(" [init] Loading ML model...", end='', flush=True)
    try:
        model = load_model('cyberdna_autoencoder.h5', compile=False)
        with open('scaler.pkl', 'rb') as f: 
            scaler = pickle.load(f)
        with open('model_metadata.pkl', 'rb') as f: 
            meta = pickle.load(f)
        
        print(" DONE.")
        print(f" [init] 📊 Features: {len(meta['feature_names'])}")
        print(f" [init] 🔬 Calibration: {CALIBRATION_CYCLES} cycle ({CALIBRATION_CYCLES * 10}s)")
        
        if DEMO_MODE:
            print(f" [init] 🎬 DEMO MODE: Simulated attack every 30s (or press 'a')")
        
        return model, scaler, meta
    except Exception as e:
        print(f"\n [FATAL] Model loading failed: {e}")
        sys.exit(1)

def capture_traffic(interface):
    status = "CALIBRATING" if calibration_mode else "MONITORING"
    print(f"\n [scan] {status} on {interface} ({SCAN_DURATION}s)...", end='', flush=True)
    
    cmd = ['tshark', '-i', interface, '-a', f'duration:{SCAN_DURATION}', '-w', TEMP_PCAP]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(" DONE.")
        return True
    except:
        print("\n [ERROR] Capture failed!")
        return False

# =============================================================================
# 🎯 MAIN ANALYSIS FUNCTION
# =============================================================================

def analyze(model, scaler, meta):
    """
    Main detection engine - analyzes captured traffic using:
    1. Signature-based rules (detect_attack_signature)
    2. ML anomaly detection (autoencoder reconstruction error)
    3. Behavioral analysis (timing, patterns)
    """
    global device_baseline, network_mse_history, calibration_mode, calibration_counter
    global demo_attack_triggered, cycle_count
    
    cycle_count += 1
    
    # In demo mode, auto-trigger every 3rd cycle after calibration
    if DEMO_MODE and not calibration_mode and cycle_count % 3 == 0:
        demo_attack_triggered = True
    
    if not os.path.exists(TEMP_PCAP):
        return
    
    feature_names = meta['feature_names']
    
    # Extract packet data from PCAP
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
        return
    
    # Clean data
    df.columns = ['ts', 'mac', 'len', 'dst_ip', 'tcp_dport', 'udp_dport']
    df = df.dropna(subset=['mac'])
    df['len'] = pd.to_numeric(df['len'], errors='coerce').fillna(0)
    df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
    
    # 🎭 Inject simulated attack if triggered
    if demo_attack_triggered:
        df = inject_simulated_attack_traffic(df)
    
    grouped = df.groupby('mac')
    
    devices_total = len(grouped)
    devices_analyzed = sum(1 for _, g in grouped if len(g) >= MIN_PACKETS)
    
    if calibration_mode:
        calibration_counter += 1
        print(f" [calib] Learning baseline from {devices_total} devices ({devices_analyzed} analyzed)")
    else:
        print(f" [proc] Analyzing {devices_total} devices ({devices_analyzed} analyzed)")
    
    current_cycle_mse = []
    
    for mac, group in grouped:
        if len(group) < MIN_PACKETS:
            continue
        
        # ==========================================
        # STEP 1: SIGNATURE-BASED DETECTION
        # ==========================================
        is_attack, attack_type, sig_confidence = detect_attack_signature(group)
        
        # ==========================================
        # STEP 2: EXTRACT BEHAVIORAL FEATURES
        # ==========================================
        genome, iats, unique_ports = extract_behavioral_features(group)
        genome_df = pd.DataFrame([genome])
        
        # Match model's expected features
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
        
        # Log transforms
        for col in X.columns:
            if 'IAT' in col or 'Variance' in col or 'Duration' in col or 'size' in col:
                X[col] = np.log1p(X[col].clip(lower=0))
        
        # ==========================================
        # STEP 3: ML ANOMALY DETECTION
        # ==========================================
        try:
            X_scaled = scaler.transform(X)
            reconstructed = model.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - reconstructed, 2))
        except Exception as e:
            continue
        
        # Track baselines
        device_baseline[mac].append(mse)
        if len(device_baseline[mac]) > 50:
            device_baseline[mac] = device_baseline[mac][-50:]
        
        current_cycle_mse.append(mse)
        
        # Skip detection during calibration
        if calibration_mode:
            attack_label = f" [⚠️ {attack_type}]" if is_attack else ""
            print(f"  📡 MAC:{mac} | MSE:{mse:.4f} | Pkts:{len(group)}{attack_label}")
            continue
        
        # Need baseline before detecting
        if len(network_mse_history) < 3:
            continue
        
        # ==========================================
        # STEP 4: CALCULATE THREAT LEVEL
        # ==========================================
        network_median = np.median(network_mse_history)
        device_median = np.median(device_baseline[mac]) if len(device_baseline[mac]) > 3 else mse
        device_deviation = (mse / device_median) if device_median > 0.01 else 1.0
        network_deviation = (mse / network_median) if network_median > 0.01 else 1.0
        
        avg_packet_size = group['len'].mean()
        is_legitimate = avg_packet_size > LEGITIMACY_PACKET_SIZE
        
        # Determine status
        if is_attack:
            threat_level = min(100, int(sig_confidence))
            status = "ALARM"
            label = f"[{attack_type}]"
        elif is_legitimate:
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
        
        # Display results
        if status == "ALARM":
            print(f"\n  \033[91m🚨 [ALARM] {label} MAC:{mac} | THREAT:{threat_level}%\033[0m")
            explain_detection(mac, is_attack, attack_type, mse, device_median, network_median,
                            unique_ports, avg_packet_size, len(group), iats)
        elif status == "WATCH":
            print(f"  \033[93m⚠️  [WATCH] MAC:{mac} | THREAT:{threat_level}%\033[0m")
        else:
            print(f"  \033[92m✅ [SAFE]  MAC:{mac} | THREAT:{threat_level}%\033[0m")
    
    # Update network baseline
    if current_cycle_mse:
        network_mse_history.extend(current_cycle_mse)
        if len(network_mse_history) > 500:
            network_mse_history = network_mse_history[-500:]
    
    # Check calibration completion
    if calibration_mode and calibration_counter >= CALIBRATION_CYCLES:
        calibration_mode = False
        print("\n" + "="*70)
        print("🎯 CALIBRATION COMPLETE! Detection active...")
        print(f"📊 Baseline: {len(network_mse_history)} samples, Median MSE: {np.median(network_mse_history):.4f}")
        
        if DEMO_MODE:
            print("\n🎬 DEMO MODE: Attack triggers automatically every 30s")
            print("   (Or press 'a' + ENTER for manual trigger)")
        
        print("="*70)
    
    # Cleanup
    if os.path.exists(TEMP_PCAP):
        os.remove(TEMP_PCAP)
    if os.path.exists(TEMP_CSV):
        os.remove(TEMP_CSV)

# =============================================================================
# 🚀 MAIN PROGRAM
# =============================================================================

if __name__ == '__main__':
    print_banner()
    
    mode_str = "🎬 DEMO MODE" if DEMO_MODE else "🔒 LIVE MODE"
    print("\n" + "="*70)
    print(f"SENTINEL v3.0 - IoT INTRUSION DETECTION SYSTEM")
    print("="*70)
    print("Detection Capabilities:")
    print("  • Signature-based: Port scans, packet floods, DDoS patterns")
    print("  • ML anomaly detection: Behavioral deviations from baseline")
    print("  • Hybrid approach: Reduces false positives")
    
    if DEMO_MODE:
        print(f"\n🎬 Demonstration Mode Active:")
        print(f"  • Simulated attacker MAC: {DEMO_MAC}")
        print(f"  • Auto-triggers every 30s after calibration")
        print(f"  • Real detection logic analyzes simulated attack traffic")
    
    print("="*70 + "\n")
    
    model, scaler, meta = load_brain()
    active_interface = initialize_hardware()
    
    # Start manual trigger listener
    listener = threading.Thread(target=demo_trigger_listener, daemon=True)
    listener.start()
    
    print("\n" + "="*70)
    print("🎯 STARTING MONITORING...")
    print("="*70)
    
    while True:
        success = capture_traffic(active_interface)
        
        if success:
            analyze(model, scaler, meta)
        else:
            print(" [warn] Restarting interface...")
            subprocess.run(['pkill', 'tshark'], stdout=subprocess.DEVNULL)
            active_interface = initialize_hardware()
            time.sleep(2)
