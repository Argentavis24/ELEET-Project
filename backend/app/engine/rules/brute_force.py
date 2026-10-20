import json
from typing import Optional, Any
from app.engine.rules.base import BaseRule, AlertCandidate
from app.core.config import settings

class BruteForceRule(BaseRule):
    def __init__(self):
        super().__init__(name="Brute-Force Authentication", default_severity="High")

    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        if flow.dst_port not in settings.BRUTE_FORCE_PORTS:
            return None

        records = window.get_src_records(flow.src_ip, settings.BRUTE_FORCE_WINDOW_SECS, current_timestamp)
        
        # Count connections to this auth port on this target
        auth_attempts = [
            r for r in records 
            if r.dst_port == flow.dst_port and r.dst_ip == flow.dst_ip
        ]
        
        attempt_count = len(auth_attempts) + 1  # include current flow

        if attempt_count >= settings.BRUTE_FORCE_ATTEMPT_THRESHOLD:
            service_names = {
                22: "SSH",
                3389: "RDP",
                21: "FTP",
                23: "Telnet",
                3306: "MySQL",
                5432: "PostgreSQL",
                8080: "HTTP-Auth"
            }
            service_desc = service_names.get(flow.dst_port, f"Port {flow.dst_port}")
            
            evidence = json.dumps({
                "service": service_desc,
                "target_port": flow.dst_port,
                "attempt_count": attempt_count,
                "target_host": flow.dst_ip,
                "time_window_seconds": settings.BRUTE_FORCE_WINDOW_SECS,
                "rate_attempts_per_sec": round(attempt_count / settings.BRUTE_FORCE_WINDOW_SECS, 2)
            })

            explanation = (
                f"Repeated credential brute-force attempts ({attempt_count} requests) detected from "
                f"{flow.src_ip} targeting {service_desc} on {flow.dst_ip} within {settings.BRUTE_FORCE_WINDOW_SECS}s."
            )

            recommended_action = (
                f"Enforce IP fail2ban/rate-limiting on port {flow.dst_port}, quarantine {flow.src_ip}, and check host auth logs."
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
                classification="Brute Force",
                risk_score=0.88
            )
        return None
