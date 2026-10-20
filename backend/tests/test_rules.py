import time
from datetime import datetime, timezone
from app.engine.sliding_window import SlidingWindow
from app.engine.rules.port_scan import PortScanRule
from app.engine.rules.brute_force import BruteForceRule
from app.engine.rules.ddos_flood import DdosFloodRule
from app.engine.rules.suspicious_traffic import SuspiciousTrafficRule
from app.engine.rules.arp_spoof import ArpSpoofRule
from app.engine.rules.blacklist import BlacklistRule
from app.schemas.flow import FlowCreate

def test_port_scan_detection():
    rule = PortScanRule()
    window = SlidingWindow()
    now = time.time()
    src_ip = "10.10.10.50"
    dst_ip = "192.168.1.10"

    # Simulate hitting 4 distinct ports
    for port in [21, 22, 23, 25]:
        window.add_flow(now, src_ip, dst_ip, 50000, port, "TCP", 1, 64)

    # 5th distinct port should trigger port scan
    flow5 = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        packet_count=1,
        byte_count=64,
        duration=0.01
    )

    alert = rule.evaluate(flow5, window, now)
    assert alert is not None
    assert alert.rule_name == "Port Scanning"
    assert alert.severity == "High"
    assert alert.classification == "Port Scan"

def test_brute_force_detection():
    rule = BruteForceRule()
    window = SlidingWindow()
    now = time.time()
    src_ip = "10.10.10.60"
    dst_ip = "192.168.1.15"

    # Add 3 attempts to SSH (port 22)
    for _ in range(3):
        window.add_flow(now, src_ip, dst_ip, 55000, 22, "TCP", 5, 300)

    # 4th attempt to SSH should trigger brute force
    flow4 = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=55000,
        dst_port=22,
        protocol="TCP",
        packet_count=5,
        byte_count=300,
        duration=0.2
    )

    alert = rule.evaluate(flow4, window, now)
    assert alert is not None
    assert alert.rule_name == "Brute-Force Authentication"
    assert alert.classification == "Brute Force"

def test_ddos_flood_detection():
    rule = DdosFloodRule()
    window = SlidingWindow()
    now = time.time()
    src_ip = "172.16.0.99"
    dst_ip = "192.168.1.10"

    # Single flow with massive packet surge
    surge_flow = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44444,
        dst_port=80,
        protocol="TCP",
        packet_count=300,
        byte_count=180000,
        duration=0.05
    )

    alert = rule.evaluate(surge_flow, window, now)
    assert alert is not None
    assert alert.rule_name == "DDoS / Volumetric Flood"
    assert alert.severity == "Critical"

def test_suspicious_traffic_detection():
    rule = SuspiciousTrafficRule()
    window = SlidingWindow()
    now = time.time()

    # Outbound flow to Metasploit port 4444
    flow_meterpreter = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.105",
        dst_ip="198.51.100.77",
        src_port=49152,
        dst_port=4444,
        protocol="TCP",
        packet_count=10,
        byte_count=1024,
        duration=1.0
    )

    alert = rule.evaluate(flow_meterpreter, window, now)
    assert alert is not None
    assert alert.rule_name == "Suspicious Outbound Traffic"

def test_arp_spoof_detection():
    rule = ArpSpoofRule()
    window = SlidingWindow()
    now = time.time()
    ip = "192.168.1.1"

    # Register initial legitimate MAC
    window.check_arp_conflict(ip, "00:1A:2B:3C:4D:01")

    # Flow arriving with different MAC for same IP
    spoofed_flow = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip=ip,
        dst_ip="192.168.1.101",
        src_port=0,
        dst_port=0,
        protocol="ARP",
        packet_count=1,
        byte_count=64,
        duration=0.01,
        mac_address="DE:AD:BE:EF:00:01"
    )

    alert = rule.evaluate(spoofed_flow, window, now)
    assert alert is not None
    assert alert.rule_name == "ARP Poisoning / MAC Spoofing"
    assert alert.severity == "Critical"

def test_blacklist_detection():
    rule = BlacklistRule()
    window = SlidingWindow()
    now = time.time()

    flow_blacklisted = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip="185.220.101.5",
        dst_ip="192.168.1.10",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_count=10,
        byte_count=800,
        duration=0.5
    )

    alert = rule.evaluate(flow_blacklisted, window, now)
    assert alert is not None
    assert alert.rule_name == "Known Malicious C2 Communication"
    assert alert.severity == "Critical"
