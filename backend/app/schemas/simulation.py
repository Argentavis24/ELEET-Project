from typing import Optional, List
from pydantic import BaseModel

class SimulationConfig(BaseModel):
    is_running: bool = False
    rate_flows_per_second: float = 2.0
    attack_probability: float = 0.20  # 20% of traffic triggers simulated attack pattern
    active_scenarios: List[str] = [
        "port_scan",
        "brute_force",
        "ddos_flood",
        "suspicious_outbound",
        "arp_spoof",
        "blacklist_comm"
    ]

class TriggerAttackRequest(BaseModel):
    scenario: str  # "port_scan", "brute_force", "ddos_flood", "suspicious_outbound", "arp_spoof", "blacklist_comm"
    target_ip: Optional[str] = None
    intensity: Optional[int] = 10

class SimulationStatus(BaseModel):
    is_running: bool
    rate_flows_per_second: float
    attack_probability: float
    total_simulated_flows: int
    total_simulated_alerts: int
    active_scenarios: List[str]
