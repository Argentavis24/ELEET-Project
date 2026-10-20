from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.core.database import Base

class QuarantinedIP(Base):
    __tablename__ = "quarantined_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    reason = Column(String(255), nullable=False)
    blocked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    blocked_by = Column(String(50), default="analyst", nullable=False)
    is_active = Column(Boolean, default=True, index=True, nullable=False)
