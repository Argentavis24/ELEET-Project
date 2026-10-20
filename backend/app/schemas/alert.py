from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class AlertBase(BaseModel):
    rule_name: str
    severity: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: str
    explanation: str
    recommended_action: str
    status: str = "NEW"
    notes: Optional[str] = None
    flow_id: Optional[int] = None

class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None

class AlertUpdate(BaseModel):
    status: Optional[str] = None  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    notes: Optional[str] = None

class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class AlertFilterParams(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    rule_name: Optional[str] = None
    src_ip: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 50
    offset: int = 0

class PaginatedAlerts(BaseModel):
    total: int
    alerts: List[AlertResponse]
    page: int
    limit: int
