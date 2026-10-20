from datetime import datetime, timedelta, timezone
import random
import json
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import get_password_hash
from app.models.user import User
from app.models.flow import NetworkFlow
from app.models.alert import Alert
from app.models.quarantine import QuarantinedIP
from app.engine.detector import nids_engine

def seed_database(db: Session):
    # 1. Seed Users
    admin = db.query(User).filter(User.username == settings.DEFAULT_ADMIN_USERNAME).first()
    if not admin:
        admin = User(
            username=settings.DEFAULT_ADMIN_USERNAME,
            hashed_password=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
            full_name="Senior Security Admin",
            role="admin",
            is_active=True
        )
        db.add(admin)

    analyst = db.query(User).filter(User.username == settings.DEFAULT_ANALYST_USERNAME).first()
    if not analyst:
        analyst = User(
            username=settings.DEFAULT_ANALYST_USERNAME,
            hashed_password=get_password_hash(settings.DEFAULT_ANALYST_PASSWORD),
            full_name="Tier 2 SOC Analyst",
            role="analyst",
            is_active=True
        )
        db.add(analyst)

    db.commit()

    # 2. Check if flow data already exists
    flow_count = db.query(NetworkFlow).count()
    if flow_count >= 50:
        nids_engine.load_quarantined_ips(db)
        return

    print("Seeding initial network flows, security alerts, and quarantine records...")

    # 3. Seed Quarantined IPs
    sample_blocks = [
        ("198.51.100.23", "Known Mirai C2 Botnet IP - Confirmed Threat Actor"),
        ("10.0.0.88", "Volumetric SYN/HTTP Flood - Automated Mitigation"),
        ("185.220.101.5", "Tor Exit Node brute forcing bastion hosts")
    ]
    for ip, reason in sample_blocks:
        if not db.query(QuarantinedIP).filter(QuarantinedIP.ip_address == ip).first():
            block = QuarantinedIP(
                ip_address=ip,
                reason=reason,
                blocked_by="analyst",
                blocked_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 12)),
                is_active=True
            )
            db.add(block)
    db.commit()

    # Sync quarantine into engine
    nids_engine.load_quarantined_ips(db)

    # 4. Generate Baseline Normal Traffic
    now = datetime.now(timezone.utc)
    internal_hosts = ["192.168.1.10", "192.168.1.15", "192.168.1.25", "192.168.1.101", "192.168.1.102", "192.168.1.103"]
    external_servers = ["142.250.190.46", "151.101.65.140", "104.16.132.229", "13.107.42.14", "52.216.144.18"]

    flows_to_add = []
    
    # 90 Normal flows spread over the last 90 minutes
    for i in range(90):
        flow_time = now - timedelta(minutes=(90 - i), seconds=random.randint(0, 50))
        is_web = random.random() > 0.35
        if is_web:
            dst_port = 443 if random.random() > 0.3 else 80
            proto = "TCP"
            pkts = random.randint(5, 35)
            bytes_val = pkts * random.randint(200, 1200)
            dur = round(random.uniform(0.08, 2.5), 2)
        else:
            dst_port = random.choice([53, 22, 5432, 3306])
            proto = "UDP" if dst_port == 53 else "TCP"
            pkts = random.randint(2, 20)
            bytes_val = pkts * random.randint(80, 500)
            dur = round(random.uniform(0.02, 1.2), 2)

        flows_to_add.append(NetworkFlow(
            timestamp=flow_time,
            src_ip=random.choice(internal_hosts),
            dst_ip=random.choice(external_servers),
            src_port=random.randint(30000, 60000),
            dst_port=dst_port,
            protocol=proto,
            packet_count=pkts,
            byte_count=bytes_val,
            duration=dur,
            classification="Normal",
            risk_score=round(random.uniform(0.02, 0.15), 2),
            is_simulated=True
        ))

    db.add_all(flows_to_add)
    db.commit()

    # 5. Inject Realistic Historical Alerts & Corresponding Flows
    alert_templates = [
        {
            "rule": "Port Scanning",
            "sev": "High",
            "src": "192.168.1.199",
            "dst": "192.168.1.10",
            "port": 80,
            "proto": "TCP",
            "evidence": json.dumps({"probed_ports": [21, 22, 23, 25, 80, 443, 3306, 8080], "distinct_count": 8, "window_seconds": 12.0}),
            "explanation": "Source IP 192.168.1.199 probed 8 distinct ports on 192.168.1.10 within 12s.",
            "rec": "Quarantine IP 192.168.1.199 and check host vulnerability reports.",
            "status": "INVESTIGATING",
            "notes": "Analyst: Initial recon identified. Host assigned to dev team subnet. Following up with sysadmin.",
            "time_offset_min": 45
        },
        {
            "rule": "Brute-Force Authentication",
            "sev": "High",
            "src": "192.168.1.205",
            "dst": "192.168.1.15",
            "port": 22,
            "proto": "TCP",
            "evidence": json.dumps({"service": "SSH", "attempt_count": 6, "target_port": 22, "window_seconds": 15.0}),
            "explanation": "Repeated credential brute-force attempts (6 requests) detected from 192.168.1.205 targeting SSH on 192.168.1.15.",
            "rec": "Enforce IP rate-limiting on port 22 and review authentication logs.",
            "status": "ACKNOWLEDGED",
            "notes": "Analyst: Checked auth log, multiple invalid user attempts for 'root' and 'admin'.",
            "time_offset_min": 30
        },
        {
            "rule": "DDoS / Volumetric Flood",
            "sev": "Critical",
            "src": "10.0.0.88",
            "dst": "192.168.1.10",
            "port": 80,
            "proto": "TCP",
            "evidence": json.dumps({"total_packets": 620, "flows_in_window": 30, "packets_per_sec": 124.0, "estimated_mbps": 18.5}),
            "explanation": "Volumetric DDoS surge detected from 10.0.0.88: 620 packets (124 pps, ~18.5 Mbps) directed at web server 192.168.1.10:80.",
            "rec": "Immediately block source IP at perimeter edge firewall.",
            "status": "RESOLVED",
            "notes": "Analyst: Automated mitigation engaged, IP added to active quarantine blocklist.",
            "time_offset_min": 20
        },
        {
            "rule": "Suspicious Outbound Traffic",
            "sev": "Critical",
            "src": "192.168.1.104",
            "dst": "198.51.100.44",
            "port": 4444,
            "proto": "TCP",
            "evidence": json.dumps({"destination_port": 4444, "threat_intel": "Metasploit Meterpreter Default Listener", "byte_count": 8450000}),
            "explanation": "Suspicious outbound activity from 192.168.1.104 towards 198.51.100.44: connection to known threat port 4444 and 8.45 MB transfer.",
            "rec": "Sever outbound connection, isolate workstation 192.168.1.104, extract triage package.",
            "status": "NEW",
            "notes": None,
            "time_offset_min": 10
        },
        {
            "rule": "ARP Poisoning / MAC Spoofing",
            "sev": "Critical",
            "src": "192.168.1.1",
            "dst": "192.168.1.101",
            "port": 0,
            "proto": "ARP",
            "evidence": json.dumps({"ip_address": "192.168.1.1", "claimed_mac": "DE:AD:BE:EF:CA:FE", "legitimate_mac": "00:1A:2B:3C:4D:01"}),
            "explanation": "ARP spoofing conflict detected on subnet: Gateway IP 192.168.1.1 was claimed by unauthorized MAC DE:AD:BE:EF:CA:FE.",
            "rec": "Verify switch port security (DAI) and inspect physical network segment for rogue device.",
            "status": "NEW",
            "notes": None,
            "time_offset_min": 5
        },
        {
            "rule": "Known Malicious C2 Communication",
            "sev": "Critical",
            "src": "185.220.101.5",
            "dst": "192.168.1.102",
            "port": 9001,
            "proto": "TCP",
            "evidence": json.dumps({"blacklisted_ip": "185.220.101.5", "direction": "Inbound from Malicious Host", "feed": "Tor Exit / Threat C2"}),
            "explanation": "Inbound connection detected involving blacklisted IP 185.220.101.5 on port 9001. Host is known Tor C2 relay.",
            "rec": "Quarantine local host 192.168.1.102 and block IP in border gateway.",
            "status": "NEW",
            "notes": None,
            "time_offset_min": 2
        },
        {
            "rule": "Isolation Forest Anomaly",
            "sev": "Medium",
            "src": "192.168.1.103",
            "dst": "104.16.132.229",
            "port": 8443,
            "proto": "TCP",
            "evidence": json.dumps({"ml_model": "Isolation Forest", "anomaly_score": 0.81, "decision_function": -0.142}),
            "explanation": "Statistical anomaly detected by Isolation Forest model on flow from 192.168.1.103 to 104.16.132.229:8443. High bytes-per-packet ratio.",
            "rec": "Inspect client application and verify payload integrity.",
            "status": "ACKNOWLEDGED",
            "notes": "Analyst: High-volume legitimate firmware update download verified by network admin.",
            "time_offset_min": 15
        }
    ]

    for item in alert_templates:
        alert_time = now - timedelta(minutes=item["time_offset_min"])
        
        # Create corresponding flow
        flow = NetworkFlow(
            timestamp=alert_time,
            src_ip=item["src"],
            dst_ip=item["dst"],
            src_port=random.randint(40000, 60000),
            dst_port=item["port"],
            protocol=item["proto"],
            packet_count=random.randint(15, 80),
            byte_count=random.randint(2000, 50000),
            duration=round(random.uniform(0.1, 2.0), 2),
            classification=item["rule"],
            risk_score=0.92 if item["sev"] == "Critical" else (0.85 if item["sev"] == "High" else 0.75),
            alert_reason=item["explanation"],
            mac_address="DE:AD:BE:EF:CA:FE" if "ARP" in item["rule"] else "00:1A:2B:3C:4D:99",
            is_simulated=True
        )
        db.add(flow)
        db.commit()
        db.refresh(flow)

        alert = Alert(
            timestamp=alert_time,
            rule_name=item["rule"],
            severity=item["sev"],
            src_ip=item["src"],
            dst_ip=item["dst"],
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            evidence=item["evidence"],
            explanation=item["explanation"],
            recommended_action=item["rec"],
            status=item["status"],
            notes=item["notes"],
            flow_id=flow.id,
            updated_at=alert_time
        )
        db.add(alert)

    db.commit()
    print("Database seeding successfully completed!")
