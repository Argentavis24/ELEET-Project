from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.core.database import get_db
from app.models.flow import NetworkFlow
from app.models.alert import Alert
from app.models.quarantine import QuarantinedIP
from app.engine.detector import nids_engine

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/metrics")
def get_dashboard_metrics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    total_flows = db.query(func.count(NetworkFlow.id)).scalar() or 0
    active_alerts = db.query(func.count(Alert.id)).filter(
        Alert.status.in_(["NEW", "ACKNOWLEDGED", "INVESTIGATING"])
    ).scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.severity == "Critical",
        Alert.status.in_(["NEW", "ACKNOWLEDGED", "INVESTIGATING"])
    ).scalar() or 0
    quarantined_count = db.query(func.count(QuarantinedIP.id)).filter(
        QuarantinedIP.is_active == True
    ).scalar() or 0

    # Recent traffic throughput over last 60 seconds
    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(seconds=60)
    recent_stats = db.query(
        func.sum(NetworkFlow.byte_count),
        func.sum(NetworkFlow.packet_count)
    ).filter(NetworkFlow.timestamp >= recent_cutoff).first()

    recent_bytes = recent_stats[0] or 0
    recent_packets = recent_stats[1] or 0
    throughput_kbps = round((recent_bytes * 8) / (60 * 1000), 2)  # kilobits/sec
    packets_per_sec = round(recent_packets / 60, 1)

    return {
        "total_flows": total_flows,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts,
        "blocked_ips_count": quarantined_count,
        "throughput_kbps": throughput_kbps,
        "packets_per_sec": packets_per_sec,
        "system_status": {
            "engine": "Operational",
            "ml_anomaly_detector": "Online (Isolation Forest)",
            "active_rules_count": len(nids_engine.rules),
            "quarantined_ips_count": len(nids_engine.quarantined_ips),
            "database": "Connected (SQLite)"
        }
    }

@router.get("/charts")
def get_dashboard_charts(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # 1. Protocol Distribution
    proto_query = db.query(
        NetworkFlow.protocol,
        func.count(NetworkFlow.id)
    ).group_by(NetworkFlow.protocol).all()
    protocol_distribution = [
        {"protocol": proto or "OTHER", "count": count}
        for proto, count in proto_query
    ]

    # 2. Alert Severity Distribution
    severity_query = db.query(
        Alert.severity,
        func.count(Alert.id)
    ).group_by(Alert.severity).all()
    
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    severity_dict = {sev: count for sev, count in severity_query}
    alert_severity = [
        {"severity": sev, "count": severity_dict.get(sev, 0)}
        for sev in ["Critical", "High", "Medium", "Low"]
    ]

    # 3. Traffic Over Time (recent 15 sample intervals)
    # Query recent 100 flows to aggregate smooth time series
    recent_flows = db.query(NetworkFlow).order_by(desc(NetworkFlow.timestamp)).limit(120).all()
    recent_flows.reverse()
    
    # Bucket into 10-15 time points
    traffic_over_time = []
    if recent_flows:
        step = max(1, len(recent_flows) // 12)
        for i in range(0, len(recent_flows), step):
            chunk = recent_flows[i:i + step]
            if chunk:
                ts_str = chunk[-1].timestamp.strftime("%H:%M:%S")
                bytes_sum = sum(f.byte_count for f in chunk)
                packets_sum = sum(f.packet_count for f in chunk)
                threats_count = sum(1 for f in chunk if f.risk_score >= 0.70)
                traffic_over_time.append({
                    "time": ts_str,
                    "bytes": bytes_sum,
                    "packets": packets_sum,
                    "threats": threats_count,
                    "flows": len(chunk)
                })

    # 4. Top Source IPs
    top_src_query = db.query(
        NetworkFlow.src_ip,
        func.count(NetworkFlow.id).label("flow_count"),
        func.sum(NetworkFlow.byte_count).label("total_bytes"),
        func.max(NetworkFlow.risk_score).label("max_risk")
    ).group_by(NetworkFlow.src_ip).order_by(desc("flow_count")).limit(6).all()

    top_source_ips = [
        {
            "ip": row[0],
            "flows": row[1],
            "bytes": row[2] or 0,
            "max_risk": round(row[3] or 0.0, 2),
            "is_blocked": row[0] in nids_engine.quarantined_ips
        }
        for row in top_src_query
    ]

    # 5. Top Destination IPs
    top_dst_query = db.query(
        NetworkFlow.dst_ip,
        func.count(NetworkFlow.id).label("flow_count")
    ).group_by(NetworkFlow.dst_ip).order_by(desc("flow_count")).limit(6).all()

    top_destination_ips = [
        {"ip": row[0], "flows": row[1]}
        for row in top_dst_query
    ]

    return {
        "protocol_distribution": protocol_distribution,
        "alert_severity": alert_severity,
        "traffic_over_time": traffic_over_time,
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips
    }
