from app.engine.ml_detector import MLAnomalyDetector
from app.schemas.flow import FlowCreate
from datetime import datetime, timezone

def test_ml_anomaly_detector_scoring():
    detector = MLAnomalyDetector()
    assert detector.is_trained == True

    # Standard normal HTTP flow
    normal_flow = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.101",
        dst_ip="142.250.190.46",
        src_port=49500,
        dst_port=443,
        protocol="TCP",
        packet_count=12,
        byte_count=8000,
        duration=1.2
    )

    risk_score, is_anomaly, details = detector.score_flow(normal_flow)
    assert 0.0 <= risk_score <= 0.65
    assert "anomaly_risk_score" in details

    # Extreme anomalous flow: tiny duration, 20,000 packets, millions of bytes on weird high port
    anomaly_flow = FlowCreate(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.200",
        dst_ip="198.51.100.99",
        src_port=12345,
        dst_port=61234,
        protocol="UDP",
        packet_count=20000,
        byte_count=25000000,
        duration=0.001
    )

    anom_score, anom_flag, _ = detector.score_flow(anomaly_flow)
    assert anom_score >= 0.70
    assert anom_flag == True
