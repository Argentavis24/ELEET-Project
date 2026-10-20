import json
from typing import Optional, Any
from app.engine.rules.base import BaseRule, AlertCandidate
from app.core.config import settings

class SuspiciousTrafficRule(BaseRule):
    def __init__(self):
        super().__init__(name="Suspicious Outbound Traffic", default_severity="High")

    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        is_suspicious_port = flow.dst_port in settings.SUSPICIOUS_OUTBOUND_PORTS
        is_massive_transfer = flow.byte_count >= settings.SUSPICIOUS_BYTE_THRESHOLD

        if is_suspicious_port or is_massive_transfer:
            severity = "Critical" if (is_suspicious_port and is_massive_transfer) else "High"
            
            port_indicators = {
                4444: "Metasploit Meterpreter Default Listener",
                1337: "Hacker / Backdoor Trojan Port",
                6667: "IRC Botnet Command Channel",
                31337: "BackOrifice Remote Access Trojan",
                8888: "Unauthenticated Proxy / Reverse Shell",
                9999: "Abnormal Custom Listener",
                5555: "Android ADB / Remote Debugging Exploit"
            }
            port_label = port_indicators.get(flow.dst_port, "Unassigned / Anomalous High Port")

            evidence = json.dumps({
                "destination_port": flow.dst_port,
                "port_threat_intel": port_label if is_suspicious_port else "Standard Port with Data Exfiltration",
                "byte_count": flow.byte_count,
                "packet_count": flow.packet_count,
                "duration_seconds": flow.duration,
                "is_suspicious_port": is_suspicious_port,
                "is_massive_transfer": is_massive_transfer
            })

            reasons = []
            if is_suspicious_port:
                reasons.append(f"connection to known threat port {flow.dst_port} ({port_label})")
            if is_massive_transfer:
                mb_transferred = round(flow.byte_count / (1024 * 1024), 2)
                reasons.append(f"large outbound payload transfer of {mb_transferred} MB")

            explanation = (
                f"Suspicious outbound activity from {flow.src_ip} towards {flow.dst_ip}: "
                f"{' and '.join(reasons)}."
            )

            recommended_action = (
                f"Sever outbound connection from host {flow.src_ip}, isolate device for forensic artifact extraction, and review endpoint EDR."
            )

            return AlertCandidate(
                rule_name=self.name,
                severity=severity,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                evidence=evidence,
                explanation=explanation,
                recommended_action=recommended_action,
                classification="Suspicious Outbound",
                risk_score=0.88 if severity == "Critical" else 0.82
            )
        return None
