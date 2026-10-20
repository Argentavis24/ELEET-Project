from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Index
from app.core.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    rule_name = Column(String(100), index=True, nullable=False)
    severity = Column(String(20), index=True, nullable=False)  # Low, Medium, High, Critical
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    evidence = Column(String(2000), nullable=False)  # JSON formatted evidence
    explanation = Column(String(500), nullable=False)
    recommended_action = Column(String(500), nullable=False)
    status = Column(String(30), default="NEW", index=True, nullable=False)  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    notes = Column(String(2000), nullable=True)
    flow_id = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index('idx_alerts_severity_status', 'severity', 'status'),
        Index('idx_alerts_src_timestamp', 'src_ip', 'timestamp'),
    )
