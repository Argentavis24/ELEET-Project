import time
from datetime import datetime, timezone
from typing import Tuple, Optional, List, Set
from sqlalchemy.orm import Session
from app.engine.sliding_window import SlidingWindow
from app.engine.rules import (
    BaseRule, AlertCandidate,
    PortScanRule, BruteForceRule, DdosFloodRule,
    SuspiciousTrafficRule, ArpSpoofRule, BlacklistRule
)
from app.engine.ml_detector import MLAnomalyDetector
from app.models.flow import NetworkFlow
from app.models.alert import Alert
from app.models.quarantine import QuarantinedIP
from app.schemas.flow import FlowCreate

class NIDSEngine:
    def __init__(self):
        self.window = SlidingWindow(default_ttl=60.0)
        self.rules: List[BaseRule] = [
            BlacklistRule(),
            ArpSpoofRule(),
            DdosFloodRule(),
            PortScanRule(),
            BruteForceRule(),
            SuspiciousTrafficRule()
        ]
        self.ml_detector = MLAnomalyDetector()
        self.quarantined_ips: Set[str] = set()

    def load_quarantined_ips(self, db: Session):
        """Sync quarantined IPs from database"""
        active_blocks = db.query(QuarantinedIP.ip_address).filter(QuarantinedIP.is_active == True).all()
        self.quarantined_ips = {row[0] for row in active_blocks}

    def add_quarantine(self, ip_address: str):
        self.quarantined_ips.add(ip_address)

    def remove_quarantine(self, ip_address: str):
        self.quarantined_ips.discard(ip_address)

    def process_flow(self, flow_data: FlowCreate, db: Session) -> Tuple[NetworkFlow, Optional[Alert]]:
        current_time = time.time()
        now_dt = flow_data.timestamp or datetime.now(timezone.utc)
        
        # 1. Check Active Quarantine / Blocklist
        if flow_data.src_ip in self.quarantined_ips or flow_data.dst_ip in self.quarantined_ips:
            blocked_ip = flow_data.src_ip if flow_data.src_ip in self.quarantined_ips else flow_data.dst_ip
            flow = NetworkFlow(
                timestamp=now_dt,
                src_ip=flow_data.src_ip,
                dst_ip=flow_data.dst_ip,
                src_port=flow_data.src_port,
                dst_port=flow_data.dst_port,
                protocol=flow_data.protocol.upper(),
                packet_count=flow_data.packet_count,
                byte_count=flow_data.byte_count,
                duration=flow_data.duration,
                classification="Blocked (Quarantine)",
                risk_score=1.0,
                alert_reason=f"Dropped: {blocked_ip} is in active quarantine",
                mac_address=flow_data.mac_address,
                is_simulated=flow_data.is_simulated
            )
            db.add(flow)
            db.commit()
            db.refresh(flow)
            return flow, None

        # 2. Add to Sliding Window state
        self.window.add_flow(
            timestamp=current_time,
            src_ip=flow_data.src_ip,
            dst_ip=flow_data.dst_ip,
            src_port=flow_data.src_port,
            dst_port=flow_data.dst_port,
            protocol=flow_data.protocol.upper(),
            packet_count=flow_data.packet_count,
            byte_count=flow_data.byte_count,
            mac_address=flow_data.mac_address
        )

        # 3. Evaluate Rule-based Heuristics
        candidate_alert: Optional[AlertCandidate] = None
        for rule in self.rules:
            candidate = rule.evaluate(flow_data, self.window, current_time)
            if candidate:
                candidate_alert = candidate
                break

        # 4. If no heuristic triggered, run ML Isolation Forest
        if not candidate_alert:
            ml_candidate = self.ml_detector.evaluate(flow_data)
            if ml_candidate:
                candidate_alert = ml_candidate

        # 5. Determine Classification and Risk Score
        classification = "Normal"
        risk_score = 0.05
        alert_reason = None
        alert_obj: Optional[Alert] = None

        if candidate_alert:
            classification = candidate_alert.classification
            risk_score = candidate_alert.risk_score
            alert_reason = candidate_alert.explanation

            # Check alert throttling / deduplication to prevent flooding SOC
            should_suppress = self.window.should_suppress_alert(
                flow_data.src_ip, candidate_alert.rule_name, current_time, cooldown=10.0
            )

            if not should_suppress:
                alert_obj = Alert(
                    timestamp=now_dt,
                    rule_name=candidate_alert.rule_name,
                    severity=candidate_alert.severity,
                    src_ip=candidate_alert.src_ip,
                    dst_ip=candidate_alert.dst_ip,
                    src_port=candidate_alert.src_port,
                    dst_port=candidate_alert.dst_port,
                    protocol=candidate_alert.protocol,
                    evidence=candidate_alert.evidence,
                    explanation=candidate_alert.explanation,
                    recommended_action=candidate_alert.recommended_action,
                    status="NEW"
                )
                db.add(alert_obj)
        else:
            # Baseline ML score for normal flow
            baseline_score, _, _ = self.ml_detector.score_flow(flow_data)
            risk_score = round(baseline_score * 0.35, 2)  # scale normal baseline into low risk [0.01 - 0.25]

        # 6. Save Flow Record
        flow = NetworkFlow(
            timestamp=now_dt,
            src_ip=flow_data.src_ip,
            dst_ip=flow_data.dst_ip,
            src_port=flow_data.src_port,
            dst_port=flow_data.dst_port,
            protocol=flow_data.protocol.upper(),
            packet_count=flow_data.packet_count,
            byte_count=flow_data.byte_count,
            duration=flow_data.duration,
            classification=classification,
            risk_score=risk_score,
            alert_reason=alert_reason,
            mac_address=flow_data.mac_address,
            is_simulated=flow_data.is_simulated
        )
        db.add(flow)
        db.commit()
        db.refresh(flow)

        if alert_obj:
            alert_obj.flow_id = flow.id
            db.commit()
            db.refresh(alert_obj)

        return flow, alert_obj

# Global engine singleton
nids_engine = NIDSEngine()
