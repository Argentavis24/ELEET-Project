import json
import math
from typing import Tuple, Optional, Dict, Any, List
import numpy as np
from sklearn.ensemble import IsolationForest
from app.engine.rules.base import AlertCandidate

class MLAnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1
        )
        self.is_trained = False
        self._train_baseline()

    def _extract_features(self, duration: float, packet_count: int, byte_count: int, 
                          dst_port: int, protocol: str) -> np.ndarray:
        p_code = 1.0 if protocol.upper() == "TCP" else (2.0 if protocol.upper() == "UDP" else 3.0)
        dur = max(duration, 0.001)
        b_per_p = byte_count / max(packet_count, 1)
        p_per_s = packet_count / dur
        b_per_s = byte_count / dur
        port_norm = dst_port / 65535.0
        
        return np.array([
            math.log1p(dur),
            math.log1p(packet_count),
            math.log1p(byte_count),
            math.log1p(b_per_p),
            math.log1p(min(p_per_s, 100000.0)),
            math.log1p(min(b_per_s, 100_000_000.0)),
            port_norm,
            p_code
        ], dtype=np.float32)

    def _train_baseline(self):
        """Fit model with baseline distribution of standard normal traffic"""
        np.random.seed(self.random_state)
        sample_size = 1200
        data = []

        # Normal Web HTTP/HTTPS (ports 80, 443)
        for _ in range(600):
            dur = np.random.uniform(0.05, 3.5)
            pkts = int(np.random.normal(15, 6))
            pkts = max(3, pkts)
            bytes_val = pkts * int(np.random.normal(800, 200))
            bytes_val = max(pkts * 64, bytes_val)
            port = 443 if np.random.rand() > 0.3 else 80
            data.append(self._extract_features(dur, pkts, bytes_val, port, "TCP"))

        # Normal DNS (port 53 UDP)
        for _ in range(300):
            dur = np.random.uniform(0.01, 0.15)
            pkts = np.random.choice([1, 2, 4])
            bytes_val = pkts * int(np.random.uniform(60, 220))
            data.append(self._extract_features(dur, pkts, bytes_val, 53, "UDP"))

        # Normal Internal DB/SSH (ports 5432, 3306, 22)
        for _ in range(300):
            dur = np.random.uniform(0.5, 15.0)
            pkts = int(np.random.normal(30, 10))
            pkts = max(5, pkts)
            bytes_val = pkts * int(np.random.normal(500, 150))
            port = np.random.choice([22, 3306, 5432])
            data.append(self._extract_features(dur, pkts, bytes_val, port, "TCP"))

        X = np.vstack(data)
        self.model.fit(X)
        self.is_trained = True

    def score_flow(self, flow: Any) -> Tuple[float, bool, Dict[str, Any]]:
        """
        Calculates an anomaly risk score between 0.0 (normal) and 1.0 (extreme anomaly).
        Returns (risk_score, is_anomaly, feature_dict).
        """
        features = self._extract_features(
            flow.duration, flow.packet_count, flow.byte_count, flow.dst_port, flow.protocol
        ).reshape(1, -1)

        # decision_function gives negative values for anomalies, positive for normal
        raw_score = self.model.decision_function(features)[0]
        prediction = self.model.predict(features)[0]  # -1 = anomaly, 1 = normal
        
        # Transform raw decision function score into a normalized [0.0, 1.0] risk score
        # raw_score typically ranges from ~ -0.3 (extreme anomaly) to +0.25 (typical normal)
        # We invert so higher score = higher risk
        normalized_risk = 1.0 / (1.0 + math.exp(raw_score * 12.0))
        normalized_risk = round(min(max(normalized_risk, 0.02), 0.99), 2)
        
        is_anomaly = bool(prediction == -1 or normalized_risk >= 0.70)
        
        feature_dict = {
            "duration": round(flow.duration, 3),
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "bytes_per_packet": round(flow.byte_count / max(flow.packet_count, 1), 1),
            "decision_function": round(float(raw_score), 4),
            "anomaly_risk_score": normalized_risk
        }
        
        return normalized_risk, is_anomaly, feature_dict

    def evaluate(self, flow: Any) -> Optional[AlertCandidate]:
        risk_score, is_anomaly, feature_dict = self.score_flow(flow)
        
        if is_anomaly and risk_score >= 0.75:
            severity = "High" if risk_score >= 0.85 else "Medium"
            
            evidence = json.dumps({
                "ml_model": "Isolation Forest (Unsupervised Ensemble)",
                "anomaly_score": risk_score,
                "flow_metrics": feature_dict,
                "confidence": "High" if risk_score >= 0.85 else "Medium"
            })
            
            explanation = (
                f"Statistical anomaly detected by Isolation Forest model on flow from {flow.src_ip} to "
                f"{flow.dst_ip}:{flow.dst_port}. Flow feature geometry deviates significantly from normal traffic baseline."
            )
            
            recommended_action = (
                f"Inspect host {flow.src_ip} behavior, verify application payload on port {flow.dst_port}, "
                f"and monitor for data staging or beaconing."
            )

            return AlertCandidate(
                rule_name="Isolation Forest Anomaly",
                severity=severity,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                evidence=evidence,
                explanation=explanation,
                recommended_action=recommended_action,
                classification="ML Anomaly",
                risk_score=risk_score
            )
        return None
