import random
import time
import asyncio
from datetime import datetime, timezone
from typing import List, Optional, Callable, Dict, Any
from app.schemas.flow import FlowCreate
from app.core.config import settings

class TrafficGenerator:
    def __init__(self):
        self.is_running: bool = False
        self.rate_flows_per_second: float = 2.0
        self.attack_probability: float = 0.25
        self.total_simulated_flows: int = 0
        self.total_simulated_alerts: int = 0
        self.active_scenarios: List[str] = [
            "port_scan",
            "brute_force",
            "ddos_flood",
            "suspicious_outbound",
            "arp_spoof",
            "blacklist_comm"
        ]
        self._dispatch_callback: Optional[Callable] = None
        self._task: Optional[asyncio.Task] = None

        # Network topology pools
        self.internal_ips = [
            "192.168.1.10",  # App Server
            "192.168.1.15",  # Database Server
            "192.168.1.25",  # Domain Controller
            "192.168.1.101", # Workstation Alpha
            "192.168.1.102", # Workstation Beta
            "192.168.1.103", # Workstation Gamma
            "192.168.1.104", # Dev Machine
            "192.168.1.105", # Analyst Laptop
        ]
        self.external_ips = [
            "142.250.190.46",  # Google DNS/Cloud
            "151.101.65.140",  # Fastly CDN
            "104.16.132.229",  # Cloudflare
            "13.107.42.14",    # Microsoft Azure
            "52.216.144.18",   # AWS S3
        ]
        self.known_macs = {
            "192.168.1.1": "00:1A:2B:3C:4D:01",   # Default Gateway
            "192.168.1.10": "00:1A:2B:3C:4D:10",
            "192.168.1.15": "00:1A:2B:3C:4D:15",
            "192.168.1.101": "52:54:00:12:34:56",
            "192.168.1.102": "52:54:00:78:9A:BC",
        }

    def set_callback(self, callback: Callable):
        self._dispatch_callback = callback

    def generate_normal_flow(self) -> FlowCreate:
        proto = random.choices(["TCP", "UDP"], weights=[0.85, 0.15])[0]
        src = random.choice(self.internal_ips)
        dst = random.choice(self.external_ips)
        
        if proto == "TCP":
            dst_port = random.choices(
                [443, 80, 8080, 22, 5432, 3306],
                weights=[0.60, 0.20, 0.08, 0.04, 0.04, 0.04]
            )[0]
            src_port = random.randint(32768, 61000)
            duration = round(random.uniform(0.05, 4.0), 3)
            packets = random.randint(4, 45)
            bytes_val = packets * random.randint(150, 1400)
        else:  # UDP
            dst_port = 53  # DNS
            src_port = random.randint(32768, 61000)
            duration = round(random.uniform(0.01, 0.2), 3)
            packets = random.choice([1, 2, 4])
            bytes_val = packets * random.randint(64, 256)

        mac = self.known_macs.get(src, f"52:54:00:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}")

        return FlowCreate(
            timestamp=datetime.now(timezone.utc),
            src_ip=src,
            dst_ip=dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            packet_count=packets,
            byte_count=bytes_val,
            duration=duration,
            mac_address=mac,
            is_simulated=True
        )

    def generate_port_scan_flows(self, target_ip: Optional[str] = None) -> List[FlowCreate]:
        attacker_ip = "192.168.1.199"
        target = target_ip or "192.168.1.10"
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 8080]
        flows = []
        now = datetime.now(timezone.utc)
        for port in ports[:7]:
            flows.append(FlowCreate(
                timestamp=now,
                src_ip=attacker_ip,
                dst_ip=target,
                src_port=random.randint(40000, 50000),
                dst_port=port,
                protocol="TCP",
                packet_count=1,
                byte_count=64,
                duration=0.01,
                mac_address="52:54:00:AA:BB:CC",
                is_simulated=True
            ))
        return flows

    def generate_brute_force_flows(self, target_ip: Optional[str] = None, port: int = 22) -> List[FlowCreate]:
        attacker_ip = "192.168.1.205"
        target = target_ip or "192.168.1.15"
        flows = []
        now = datetime.now(timezone.utc)
        for _ in range(5):
            flows.append(FlowCreate(
                timestamp=now,
                src_ip=attacker_ip,
                dst_ip=target,
                src_port=random.randint(30000, 60000),
                dst_port=port,
                protocol="TCP",
                packet_count=random.randint(3, 8),
                byte_count=random.randint(250, 600),
                duration=round(random.uniform(0.1, 0.4), 2),
                mac_address="52:54:00:DD:EE:FF",
                is_simulated=True
            ))
        return flows

    def generate_ddos_flows(self, target_ip: Optional[str] = None) -> List[FlowCreate]:
        attacker_ip = "10.0.0.88"
        target = target_ip or "192.168.1.10"
        flows = []
        now = datetime.now(timezone.utc)
        for _ in range(12):
            flows.append(FlowCreate(
                timestamp=now,
                src_ip=attacker_ip,
                dst_ip=target,
                src_port=random.randint(1024, 65535),
                dst_port=80,
                protocol="TCP",
                packet_count=random.randint(45, 80),
                byte_count=random.randint(15000, 45000),
                duration=round(random.uniform(0.01, 0.05), 3),
                mac_address="52:54:00:11:22:33",
                is_simulated=True
            ))
        return flows

    def generate_suspicious_outbound_flow(self, target_ip: Optional[str] = None) -> FlowCreate:
        internal_src = "192.168.1.104"
        external_c2 = target_ip or "198.51.100.44"
        port = random.choice(settings.SUSPICIOUS_OUTBOUND_PORTS)
        is_large = random.choice([True, False])
        bytes_val = random.randint(6_000_000, 12_000_000) if is_large else random.randint(2000, 8000)
        packets = random.randint(400, 2000) if is_large else random.randint(10, 30)

        return FlowCreate(
            timestamp=datetime.now(timezone.utc),
            src_ip=internal_src,
            dst_ip=external_c2,
            src_port=random.randint(35000, 60000),
            dst_port=port,
            protocol="TCP",
            packet_count=packets,
            byte_count=bytes_val,
            duration=round(random.uniform(1.2, 5.5), 2),
            mac_address="52:54:00:78:9A:BC",
            is_simulated=True
        )

    def generate_arp_spoof_flow(self) -> FlowCreate:
        gateway_ip = "192.168.1.1"
        # Seed legitimate first if not known
        rogue_mac = "DE:AD:BE:EF:CA:FE"
        return FlowCreate(
            timestamp=datetime.now(timezone.utc),
            src_ip=gateway_ip,
            dst_ip="192.168.1.101",
            src_port=0,
            dst_port=0,
            protocol="ARP",
            packet_count=2,
            byte_count=128,
            duration=0.01,
            mac_address=rogue_mac,
            is_simulated=True
        )

    def generate_blacklist_flow(self) -> FlowCreate:
        blacklisted = random.choice(settings.KNOWN_BLACKLISTED_IPS)
        internal_host = random.choice(self.internal_ips)
        direction = random.choice(["inbound", "outbound"])
        src = blacklisted if direction == "inbound" else internal_host
        dst = internal_host if direction == "inbound" else blacklisted
        
        return FlowCreate(
            timestamp=datetime.now(timezone.utc),
            src_ip=src,
            dst_ip=dst,
            src_port=random.randint(30000, 60000),
            dst_port=random.choice([443, 8080, 9001]),
            protocol="TCP",
            packet_count=random.randint(12, 35),
            byte_count=random.randint(2000, 6000),
            duration=round(random.uniform(0.3, 1.8), 2),
            mac_address="52:54:00:FF:00:11",
            is_simulated=True
        )

    def trigger_scenario(self, scenario: str, target_ip: Optional[str] = None) -> List[FlowCreate]:
        if scenario == "port_scan":
            return self.generate_port_scan_flows(target_ip)
        elif scenario == "brute_force":
            return self.generate_brute_force_flows(target_ip)
        elif scenario == "ddos_flood":
            return self.generate_ddos_flows(target_ip)
        elif scenario == "suspicious_outbound":
            return [self.generate_suspicious_outbound_flow(target_ip)]
        elif scenario == "arp_spoof":
            # First seed genuine MAC if not present
            legit_mac = self.known_macs.get("192.168.1.1", "00:1A:2B:3C:4D:01")
            legit_flow = FlowCreate(
                timestamp=datetime.now(timezone.utc),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.10",
                src_port=0,
                dst_port=0,
                protocol="ARP",
                packet_count=1,
                byte_count=64,
                duration=0.01,
                mac_address=legit_mac,
                is_simulated=True
            )
            spoofed_flow = self.generate_arp_spoof_flow()
            return [legit_flow, spoofed_flow]
        elif scenario == "blacklist_comm":
            return [self.generate_blacklist_flow()]
        else:
            return [self.generate_normal_flow()]

    async def run_loop(self):
        while self.is_running:
            try:
                # Decide whether to emit normal flow or trigger attack scenario
                if random.random() < self.attack_probability and self.active_scenarios:
                    scenario = random.choice(self.active_scenarios)
                    flows = self.trigger_scenario(scenario)
                else:
                    flows = [self.generate_normal_flow()]

                for flow in flows:
                    self.total_simulated_flows += 1
                    if self._dispatch_callback:
                        await self._dispatch_callback(flow)

                # Sleep interval based on rate
                interval = 1.0 / max(self.rate_flows_per_second, 0.1)
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                await asyncio.sleep(1.0)

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._task = asyncio.create_task(self.run_loop())

    def stop(self):
        self.is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None

# Global simulation generator singleton
traffic_generator = TrafficGenerator()
