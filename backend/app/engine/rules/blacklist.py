import json
from typing import Optional, Any
from app.engine.rules.base import BaseRule, AlertCandidate
from app.core.config import settings

class BlacklistRule(BaseRule):
    def __init__(self):
        super().__init__(name="Known Malicious C2 Communication", default_severity="Critical")

    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        matched_ip = None
        direction = None
        if flow.src_ip in settings.KNOWN_BLACKLISTED_IPS:
            matched_ip = flow.src_ip
            direction = "Inbound from Malicious Host"
        elif flow.dst_ip in settings.KNOWN_BLACKLISTED_IPS:
            matched_ip = flow.dst_ip
            direction = "Outbound to Botnet C2"

        if matched_ip:
            evidence = json.dumps({
                "blacklisted_ip": matched_ip,
                "direction": direction,
                "threat_feed_match": "Emerging Threats / Tor Exit / C2 Beacon Feed",
                "flow_port": flow.dst_port,
                "protocol": flow.protocol,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count
            })

            explanation = (
                f"{direction} detected involving blacklisted IP {matched_ip} on port {flow.dst_port} ({flow.protocol}). "
                f"IP is flagged on global threat intelligence feeds for active cybercrime/C2."
            )

            recommended_action = (
                f"Quarantine local host ({flow.src_ip if direction.startswith('Outbound') else flow.dst_ip}), "
                f"block {matched_ip} across all egress edge routers, and initiate incident response."
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
                classification="Blacklisted IP",
                risk_score=0.98
            )
        return None
