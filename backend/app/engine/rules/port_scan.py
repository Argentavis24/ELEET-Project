import json
from typing import Optional, Any
from app.engine.rules.base import BaseRule, AlertCandidate
from app.core.config import settings

class PortScanRule(BaseRule):
    def __init__(self):
        super().__init__(name="Port Scanning", default_severity="High")

    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        records = window.get_src_records(flow.src_ip, settings.PORT_SCAN_WINDOW_SECS, current_timestamp)
        
        # Collect distinct destination ports
        distinct_ports = {r.dst_port for r in records}
        distinct_ports.add(flow.dst_port)

        if len(distinct_ports) >= settings.PORT_SCAN_PORT_THRESHOLD:
            ports_sample = sorted(list(distinct_ports))[:15]
            evidence = json.dumps({
                "distinct_ports_count": len(distinct_ports),
                "ports_probed": ports_sample,
                "target_host": flow.dst_ip,
                "time_window_seconds": settings.PORT_SCAN_WINDOW_SECS,
                "recent_flow_count": len(records) + 1
            })
            
            explanation = (
                f"Source IP {flow.src_ip} probed {len(distinct_ports)} distinct ports "
                f"({', '.join(map(str, ports_sample[:5]))}...) on {flow.dst_ip} within {settings.PORT_SCAN_WINDOW_SECS}s."
            )
            
            recommended_action = (
                f"Quarantine IP {flow.src_ip} to prevent lateral movement and audit firewall for unauthorized service discovery."
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
                classification="Port Scan",
                risk_score=0.85
            )
        return None
