import json
from typing import Optional, Any
from app.engine.rules.base import BaseRule, AlertCandidate

class ArpSpoofRule(BaseRule):
    def __init__(self):
        super().__init__(name="ARP Poisoning / MAC Spoofing", default_severity="Critical")

    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        if not flow.mac_address:
            return None

        has_conflict, original_mac = window.check_arp_conflict(flow.src_ip, flow.mac_address)
        
        if has_conflict:
            evidence = json.dumps({
                "ip_address": flow.src_ip,
                "claimed_mac": flow.mac_address,
                "legitimate_mac": original_mac,
                "attack_vector": "Man-In-The-Middle (MitM) ARP Cache Poisoning",
                "detected_via": "L2 Hardware Address Discrepancy"
            })

            explanation = (
                f"ARP spoofing conflict detected on subnet: IP {flow.src_ip} was previously mapped to "
                f"MAC {original_mac}, but new frames arrived claiming MAC {flow.mac_address}."
            )

            recommended_action = (
                f"Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on local switches; isolate port with MAC {flow.mac_address}."
            )

            return AlertCandidate(
                rule_name=self.name,
                severity=self.default_severity,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                evidence=evidence,
                explanation=explanation,
                recommended_action=recommended_action,
                classification="ARP Spoofing",
                risk_score=0.92
            )
        return None
