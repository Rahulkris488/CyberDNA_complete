#!/usr/bin/env python3
"""
CyberDNA Sentinel v2.0
Autonomous WiFi Intrusion Detection System

Rewritten for robustness:
 - Reliable wireless interface detection (only IEEE 802.11)
 - Detects and respects already-active monitor mode (sysfs check)
 - Native `iw` monitor enable, fallback to airmon-ng (no renaming where possible)
 - Safe behavior inside Docker (won't clobber host monitor mode)
 - Cleaner subprocess usage, error handling and informative output
"""

import time
import os
import subprocess
import pickle
import sys
import re
import shutil
import pandas as pd
import numpy as np
from datetime import datetime
from tensorflow.keras.models import load_model
import warnings
warnings.filterwarnings('ignore')

# ============= ASCII ART / Info =============
CYBERDNA_BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗ █████╗     ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔══██╗    ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║██╔██╗ ██║███████║    ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██║╚██╗██║██╔══██║    ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝██║ ╚████║██║  ██║    ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝    ║
║                                                                           ║
║              🧬 Behavioral Intrusion Detection System 🧬                  ║
║                   Real-Time WiFi Anomaly Detection                       ║
║                         Powered by Autoencoders                          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

SENTINEL_INFO = """
┌───────────────────────────────────────────────────────────────────────────┐
│  🛡️  Sentinel v2.0 - Autonomous Edge IDS                                  │
│  📡 Auto-detecting wireless interfaces...                                 │
│  🔧 Auto-configuring monitor mode...                                      │
│  🧠 Loading neural network model...                                       │
└───────────────────────────────────────────────────────────────────────────┘
"""

# ============= CONFIGURATION =============
SCAN_DURATION = 10   # Capture window in seconds
TEMP_PCAP = '/tmp/cyberdna_buffer.pcap'

MODEL_PATH = 'cyberdna_unified_autoencoder.h5'
SCALER_PATH = 'cyberdna_unified_scaler.pkl'
METADATA_PATH = 'cyberdna_unified_metadata.pkl'

ALERT_THRESHOLD_MULTIPLIER = 1.0
HIGH_SEVERITY_MULTIPLIER = 1.5

# ============= UTILITIES =============
def print_banner():
    print("\033[1;36m" + CYBERDNA_BANNER + "\033[0m")
    print(SENTINEL_INFO)

def check_root():
    if os.geteuid() != 0:
        print("\033[1;31m❌ ERROR: Sentinel must run as root for packet capture!\033[0m")
        print("\033[1;33m   Try: sudo python3 sentinel_v2.py\033[0m\n")
        sys.exit(1)

def tool_exists(name):
    return shutil.which(name) is not None

# ============= WIRELESS DETECTION & MONITOR MODE =============
def _iwconfig_blocks():
    """Return the raw iwconfig output split into blocks per interface."""
    try:
        out = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT, text=True)
        # separate by double newline (iwconfig prints blank line between interfaces)
        blocks = [b.strip() for b in out.split('\n\n') if b.strip()]
        return blocks, out
    except subprocess.CalledProcessError:
        return [], ""

def find_wireless_interfaces():
    """
    Return list of wireless interface names that are true Wi-Fi (IEEE 802.11).
    Prioritize wlan* interface names and preserve order from iwconfig.
    """
    print("\n🔍 Scanning for wireless interfaces...")
    blocks, full_output = _iwconfig_blocks()
    interfaces = []

    for block in blocks:
        # First line contains iface name
        first_line = block.splitlines()[0]
        m = re.match(r'^([^\s]+)', first_line)
        if not m:
            continue
        iface = m.group(1)

        # Filter out obvious non-wifi interfaces (docker, vmnet, loopbacks, enp (ethernet))
        if iface.startswith(('lo', 'docker', 'vmnet', 'veth', 'br-')) or iface.startswith('enp'):
            continue

        # Confirm IEEE 802.11 present
        if 'IEEE 802.11' in block:
            interfaces.append(iface)

    # Fallback: check /sys/class/net for wireless
    if not interfaces and os.path.exists('/sys/class/net'):
        for iface in os.listdir('/sys/class/net'):
            if iface in ('lo',):
                continue
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                interfaces.append(iface)

    if interfaces:
        # Prefer names starting with wlan
        interfaces = sorted(interfaces, key=lambda x: (not x.startswith('wlan'), x))
        print(f"   ✅ Wireless interfaces: {', '.join(interfaces)}")
        return interfaces

    print("   ❌ No wireless interfaces found!")
    return []

def check_monitor_mode_sysfs(interface):
    """
    Robust check for monitor mode using sysfs type:
    NET/IFTYPE values: 1 = ethernet/managed, 803 = monitor for mac80211 (common)
    Fallback to parsing iwconfig output if sysfs not available.
    """
    try:
        tpath = f"/sys/class/net/{interface}/type"
        if os.path.exists(tpath):
            with open(tpath, 'r') as f:
                val = f.read().strip()
                # 803 is ARPHRD_IEEE80211_RADIOTAP (monitor-like), some platforms vary
                if val == "803":
                    return True
                # Some drivers may use other values; fallthrough to iwconfig parse
    except Exception:
        pass

    # Fallback parse iwconfig output
    try:
        out = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT, text=True)
        return 'Mode:Monitor' in out or 'Mode:monitor' in out or re.search(r'\bmonitor\b', out, re.I) is not None
    except subprocess.CalledProcessError:
        return False

def enable_monitor_mode_native(interface):
    """
    Try to enable monitor mode using native 'iw' (preferred).
    This keeps the same interface name (no renaming).
    """
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['iw', interface, 'set', 'type', 'monitor'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # small pause
        time.sleep(0.8)
        return check_monitor_mode_sysfs(interface)
    except subprocess.CalledProcessError:
        return False

def enable_monitor_mode_airmon(interface):
    """
    Fallback method using airmon-ng (may rename interface to wlanXmon).
    Return new interface name or False.
    """
    if not tool_exists('airmon-ng'):
        return False
    try:
        res = subprocess.run(['airmon-ng', 'start', interface], capture_output=True, text=True, check=False)
        stdout = res.stdout.lower()
        # airmon-ng prints lines like "monitor mode enabled on wlan0mon"
        m = re.search(r'monitor mode enabled on (\w+)', stdout)
        if m:
            return m.group(1)
        # fallback: parse for "created" or suggest check
        if 'monitor' in stdout:
            return interface
        return False
    except Exception:
        return False

def enable_monitor_mode(interface):
    """
    Top-level monitor mode enabler:
      - If already monitor (sysfs), return True immediately (do not touch)
      - Try native iw method (no rename)
      - If that fails, try airmon-ng fallback
      - Return True or new interface name, or False on failure
    """
    print(f"\n🔧 Configuring {interface} for monitor mode...")

    # If already monitor on host (sysfs check) -> don't touch it
    if check_monitor_mode_sysfs(interface):
        print(f"   ✅ {interface} already in monitor mode (leaving as-is)")
        return True

    # Unblock rfkill and kill conflicts (best effort)
    if tool_exists('rfkill'):
        subprocess.run(['rfkill', 'unblock', 'wifi'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if tool_exists('airmon-ng'):
        subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Try native iw method first (preferred)
    print("   → Trying native iw method (preserve interface name)...")
    if tool_exists('iw'):
        try:
            ok = enable_monitor_mode_native(interface)
            if ok:
                print(f"   ✅ Monitor mode enabled (native) on {interface}")
                return True
        except Exception:
            pass

    # If native failed, try airmon-ng fallback (may rename)
    print("   → Native method failed, trying airmon-ng fallback...")
    new_iface = enable_monitor_mode_airmon(interface)
    if new_iface:
        # verify
        time.sleep(0.8)
        if check_monitor_mode_sysfs(new_iface if isinstance(new_iface, str) else interface):
            print(f"   ✅ Monitor mode enabled on {new_iface}")
            return new_iface
    print("   ❌ Failed to enable monitor mode")
    return False

def auto_setup_interface():
    """
    Bring together detection and enabling logic.
    - Prefer already-monitor interfaces (do not touch)
    - Otherwise prefer wlan* and attempt to enable monitor mode (native then airmon-ng)
    """
    ifaces = find_wireless_interfaces()
    if not ifaces:
        print("\n❌ No Wi-Fi adapter found. Make sure it's connected.")
        sys.exit(1)

    # 1. If any interface already in monitor mode, use it (do not change)
    for iface in ifaces:
        print(f"📡 Checking {iface} for pre-existing monitor mode...")
        if check_monitor_mode_sysfs(iface):
            print(f"   ✅ Using existing monitor-mode interface: {iface}")
            return iface

    # 2. Otherwise try to enable monitor mode on preferred interfaces (wlan* first)
    for iface in ifaces:
        print(f"\n📡 Attempting to enable monitor on: {iface}")
        result = enable_monitor_mode(iface)
        if result:
            # If airmon-ng returned a different name, use it
            if isinstance(result, str) and result != iface:
                return result
            return iface

    print("\n❌ Failed to configure any wireless interface into monitor mode!")
    sys.exit(1)

# ============= MODEL LOADING =============
def load_cyberdna_model():
    print("\n🧠 Loading CyberDNA neural network...")
    try:
        if not os.path.exists(MODEL_PATH):
            print(f"   ❌ Model file not found: {MODEL_PATH}")
            sys.exit(1)
        if not os.path.exists(SCALER_PATH):
            print(f"   ❌ Scaler file not found: {SCALER_PATH}")
            sys.exit(1)
        if not os.path.exists(METADATA_PATH):
            print(f"   ❌ Metadata file not found: {METADATA_PATH}")
            sys.exit(1)

        model = load_model(MODEL_PATH, compile=False)
        print(f"   ✅ Autoencoder loaded")

        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        print(f"   ✅ Feature scaler loaded")

        with open(METADATA_PATH, 'rb') as f:
            metadata = pickle.load(f)
        print(f"   ✅ Metadata loaded")

        genome_features = metadata['genome_features']
        base_threshold = metadata['threshold']
        log_features = metadata['log_transformed_features']

        threshold = base_threshold * ALERT_THRESHOLD_MULTIPLIER
        high_severity_threshold = base_threshold * HIGH_SEVERITY_MULTIPLIER

        print(f"\n   📊 Model Configuration:")
        print(f"      Features: {len(genome_features)}")
        print(f"      Base threshold: {base_threshold:.6f}")
        print(f"      Alert threshold: {threshold:.6f}")
        print(f"      High severity threshold: {high_severity_threshold:.6f}")

        return model, scaler, genome_features, log_features, threshold, high_severity_threshold

    except Exception as e:
        print(f"   ❌ Error loading model: {e}")
        sys.exit(1)

# ============= DATA EXTRACTION & ANALYSIS =============
def calculate_entropy(series):
    if len(series) == 0 or series.nunique() <= 1:
        return 0.0
    value_counts = series.value_counts()
    probabilities = value_counts / len(series)
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    return entropy

def capture_packets(interface):
    """
    Capture packets into TEMP_PCAP using tcpdump for SCAN_DURATION seconds.
    Returns a pandas DataFrame or None on empty capture.
    """
    try:
        # Ensure tcpdump exists
        if not tool_exists('tcpdump'):
            print("   ❌ tcpdump not found. Install tcpdump.")
            return None

        # Remove old pcap
        try:
            if os.path.exists(TEMP_PCAP):
                os.remove(TEMP_PCAP)
        except Exception:
            pass

        # Use system 'timeout' if available; otherwise use subprocess timeout
        if tool_exists('timeout'):
            cmd = [
                'timeout', str(SCAN_DURATION),
                'tcpdump', '-i', interface, '-w', TEMP_PCAP, '-n',
                'type mgt subtype beacon or type mgt subtype probe-resp or type data'
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            proc = subprocess.Popen(['tcpdump', '-i', interface, '-w', TEMP_PCAP, '-n', 'type mgt subtype beacon or type mgt subtype probe-resp or type data'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                proc.wait(timeout=SCAN_DURATION)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=2)

        if not os.path.exists(TEMP_PCAP) or os.path.getsize(TEMP_PCAP) == 0:
            return None

        # Parse with tshark
        if not tool_exists('tshark'):
            print("   ❌ tshark not found. Install Wireshark/tshark.")
            return None

        cmd = [
            'tshark', '-r', TEMP_PCAP, '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'wlan.sa',
            '-e', 'frame.len',
            '-e', 'ip.dst',
            '-e', 'tcp.dstport',
            '-e', 'udp.dstport',
            '-e', 'ip.proto',
            '-e', 'radiotap.dbm_antsignal',
            '-E', 'separator=,',
            '-E', 'quote=d'
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)

        # Clean up pcap immediately
        try:
            if os.path.exists(TEMP_PCAP):
                os.remove(TEMP_PCAP)
        except Exception:
            pass

        if not result.stdout.strip():
            return None

        lines = [line for line in result.stdout.strip().split('\n') if line.strip()]
        data = [line.split(',') for line in lines]

        df = pd.DataFrame(data, columns=[
            'timestamp', 'src_mac', 'length', 'dst_ip',
            'tcp_dport', 'udp_dport', 'protocol', 'rssi'
        ])

        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        df['length'] = pd.to_numeric(df['length'], errors='coerce')
        df['rssi'] = pd.to_numeric(df['rssi'], errors='coerce')
        df['protocol'] = pd.to_numeric(df['protocol'], errors='coerce')

        return df

    except Exception:
        return None

def extract_genome(mac_group, genome_features):
    genome = {}
    try:
        if not mac_group['rssi'].isna().all():
            genome['Mean_RSSI'] = mac_group['rssi'].mean()
        else:
            genome['Mean_RSSI'] = -65.0

        if not mac_group['rssi'].isna().all() and len(mac_group) > 1:
            genome['RSSI_Variance'] = mac_group['rssi'].var()
        else:
            genome['RSSI_Variance'] = 5.0

        genome['Mean_Packet_Size'] = mac_group['length'].mean()
        genome['Packet_Size_Variance'] = mac_group['length'].var() if len(mac_group) > 1 else 0.0

        if len(mac_group) > 1:
            times = mac_group['timestamp'].dropna().sort_values()
            if len(times) > 1:
                iats = np.diff(times)
                genome['Mean_IAT'] = np.mean(iats)
            else:
                genome['Mean_IAT'] = 0.0
        else:
            genome['Mean_IAT'] = 0.0

        genome['Packet_Size_Entropy'] = calculate_entropy(mac_group['length'])
        genome['IP_Entropy'] = calculate_entropy(mac_group['dst_ip'].dropna())

        ports = pd.concat([mac_group['tcp_dport'].dropna(), mac_group['udp_dport'].dropna()])
        genome['Port_Diversity'] = ports.nunique() if len(ports) > 0 else 0

        genome['Protocol_Diversity'] = mac_group['protocol'].nunique()
        if len(mac_group) > 1:
            times = mac_group['timestamp'].dropna()
            genome['Flow_Duration'] = times.max() - times.min() if len(times) > 1 else 0.0
        else:
            genome['Flow_Duration'] = 0.0

    except Exception:
        for feat in genome_features:
            genome.setdefault(feat, 0.0)

    return genome

def detect_anomalies(df, model, scaler, genome_features, log_features, threshold, high_severity_threshold):
    if df is None or len(df) == 0:
        print("      ⚠️  No packets captured")
        return 0

    grouped = df.groupby('src_mac')
    anomalies_found = 0
    devices_analyzed = 0

    for mac, group in grouped:
        if len(group) < 3:
            continue

        devices_analyzed += 1
        genome = extract_genome(group, genome_features)
        feature_vector = np.array([[genome[feat] for feat in genome_features]])

        for i, feat in enumerate(genome_features):
            if feat in log_features:
                feature_vector[0, i] = np.log1p(max(0, feature_vector[0, i]))

        feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=0.0, neginf=0.0)
        feature_vector_scaled = scaler.transform(feature_vector)

        reconstruction = model.predict(feature_vector_scaled, verbose=0)
        mse = np.mean(np.square(feature_vector_scaled - reconstruction))

        if mse > high_severity_threshold:
            severity = "\033[1;31m🔴 CRITICAL\033[0m"
            anomalies_found += 1
        elif mse > threshold:
            severity = "\033[1;33m🟡 WARNING\033[0m"
            anomalies_found += 1
        else:
            continue

        anomaly_score = (mse / threshold) * 100

        print(f"\n{'═'*75}")
        print(f"🚨 ANOMALY DETECTED - {severity}")
        print(f"{'═'*75}")
        print(f"   \033[1mDevice MAC:\033[0m {mac}")
        print(f"   \033[1mPackets Captured:\033[0m {len(group)}")
        print(f"   \033[1mReconstruction Error:\033[0m {mse:.6f}")
        print(f"   \033[1mThreshold:\033[0m {threshold:.6f}")
        print(f"   \033[1mAnomaly Score:\033[0m {anomaly_score:.1f}%")
        print(f"\n   \033[1m📊 Behavioral Signature:\033[0m")

        key_features = ['Mean_Packet_Size', 'Mean_IAT', 'Port_Diversity', 'IP_Entropy', 'RSSI_Variance']
        for feat in key_features:
            if feat in genome:
                print(f"      {feat:25} = {genome[feat]:.2f}")

        print(f"{'═'*75}")

    if devices_analyzed > 0:
        print(f"\n   📊 Scan Summary: {devices_analyzed} devices analyzed, {anomalies_found} anomalies detected")

    return anomalies_found

# ============= MAIN LOOP =============
def main():
    print_banner()
    check_root()

    # Auto-setup interface (detect or enable monitor mode)
    interface = auto_setup_interface()

    # Load ML model
    model, scaler, genome_features, log_features, threshold, high_severity_threshold = load_cyberdna_model()

    print("\n" + "═" * 75)
    print(f"🛡️  CyberDNA Sentinel Active")
    print("═" * 75)
    print(f"   Interface: {interface}")
    print(f"   Scan interval: {SCAN_DURATION}s")
    print(f"   Alert threshold: {threshold:.6f}")
    print("═" * 75)
    print("\n\033[1;32m⚡ Real-time monitoring started...\033[0m")
    print("\033[1;33m   Press Ctrl+C to stop\033[0m\n")

    cycle = 0
    total_anomalies = 0

    try:
        while True:
            cycle += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            print(f"\n{'─'*75}")
            print(f"🔄 Scan Cycle #{cycle} - {timestamp}")
            print(f"{'─'*75}")
            print(f"   📡 Capturing packets on {interface}...", end=' ', flush=True)

            df = capture_packets(interface)
            if df is not None and len(df) > 0:
                print(f"✅ ({len(df)} packets)")
                print(f"   🔍 Analyzing traffic...", end=' ', flush=True)

                anomalies = detect_anomalies(df, model, scaler, genome_features,
                                            log_features, threshold, high_severity_threshold)
                total_anomalies += anomalies

                if anomalies == 0:
                    print(f"✅ All normal")
            else:
                print(f"⚠️  No packets")

            print(f"\n   ⏳ Next scan in {SCAN_DURATION}s...")
            time.sleep(SCAN_DURATION)

    except KeyboardInterrupt:
        print("\n\n" + "═" * 75)
        print("👋 CyberDNA Sentinel Shutting Down")
        print("═" * 75)
        print(f"   Total scans completed: {cycle}")
        print(f"   Total anomalies detected: {total_anomalies}")
        print(f"   Average per scan: {total_anomalies/cycle:.2f}")
        print("═" * 75)
        print("\n\033[1;32m✅ Sentinel stopped gracefully\033[0m\n")
    except Exception as e:
        print(f"\n\033[1;31m❌ Fatal error: {e}\033[0m")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
