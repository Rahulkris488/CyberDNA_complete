# fake_attack_injector.py - Run on your Arch machine
from scapy.all import *
import time

print("🎭 Generating fake attack packets for CyberDNA demo...")

# Generate a fake port scan PCAP
packets = []
attacker_mac = "de:ad:be:ef:ca:fe"  # Fake attacker MAC
target_ip = "192.168.1.100"

# Simulate port scan (100 ports in 5 seconds)
for port in range(1, 101):
    pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / \
          IP(src="10.0.0.50", dst=target_ip) / \
          TCP(sport=54321, dport=port, flags="S")
    
    packets.append(pkt)

# Save to PCAP
wrpcap('/tmp/fake_attack.pcap', packets)
print(f"✅ Created fake attack PCAP with {len(packets)} packets")
print("📁 Saved to: /tmp/fake_attack.pcap")

# Now inject into your network interface (sentinel will see it)
print("🚀 Injecting packets into network...")
sendp(packets, iface="wlan4", inter=0.05, verbose=0)  # 50ms between packets
print("✅ Attack simulation complete!")
