import json
from typing import Optional, Any
from app.engine.rules.base import BaseRule, AlertCandidate
from app.core.config import settings

class DdosFloodRule(BaseRule):
    def __init__(self):
        super().__init__(name="DDoS / Volumetric Flood", default_severity="Critical")

    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        records = window.get_src_records(flow.src_ip, settings.DDOS_WINDOW_SECS, current_timestamp)
        
        total_packets = sum(r.packet_count for r in records) + flow.packet_count
        total_bytes = sum(r.byte_count for r in records) + flow.byte_count
        flow_count = len(records) + 1

        is_packet_spike = total_packets >= settings.DDOS_PACKET_THRESHOLD
        is_flow_spike = flow_count >= settings.DDOS_FLOW_THRESHOLD
        is_single_flow_surge = flow.packet_count >= 250

        if is_packet_spike or is_flow_spike or is_single_flow_surge:
            pps = round(total_packets / max(settings.DDOS_WINDOW_SECS, 1.0), 1)
            mbps = round((total_bytes * 8) / (max(settings.DDOS_WINDOW_SECS, 1.0) * 1_000_000), 2)
            
            evidence = json.dumps({
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "flows_in_window": flow_count,
                "packets_per_sec": pps,
                "estimated_bandwidth_mbps": mbps,
                "target_host": flow.dst_ip,
                "target_port": flow.dst_port,
                "window_seconds": settings.DDOS_WINDOW_SECS
            })

            explanation = (
                f"Volumetric DDoS / flood surge detected from {flow.src_ip}: {total_packets} packets "
                f"({pps} pps, ~{mbps} Mbps) directed at {flow.dst_ip}:{flow.dst_port} within {settings.DDOS_WINDOW_SECS}s."
            )

            recommended_action = (
                f"Quarantine {flow.src_ip} instantly at edge BGP/firewall, apply rate limiting on ingress interface, and alert SOC."
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
                classification="DDoS Flood",
                risk_score=0.95
            )
        return None
