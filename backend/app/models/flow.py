from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Index
from app.core.database import Base

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, index=True, nullable=False)
    dst_port = Column(Integer, index=True, nullable=False)
    protocol = Column(String(10), index=True, nullable=False)  # TCP, UDP, ICMP
    packet_count = Column(Integer, default=1, nullable=False)
    byte_count = Column(Integer, default=64, nullable=False)
    duration = Column(Float, default=0.01, nullable=False)  # seconds
    classification = Column(String(50), default="Normal", index=True, nullable=False)
    risk_score = Column(Float, default=0.0, index=True, nullable=False)  # 0.0 to 1.0
    alert_reason = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)
    is_simulated = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index('idx_flows_timestamp_risk', 'timestamp', 'risk_score'),
        Index('idx_flows_src_dst', 'src_ip', 'dst_ip'),
    )
