from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

class FlowBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 1
    byte_count: int = 64
    duration: float = 0.01
    mac_address: Optional[str] = None
    is_simulated: bool = True

class FlowCreate(FlowBase):
    timestamp: Optional[datetime] = None

class FlowResponse(FlowBase):
    id: int
    timestamp: datetime
    classification: str
    risk_score: float
    alert_reason: Optional[str] = None

    class Config:
        from_attributes = True

class FlowFilterParams(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    classification: Optional[str] = None
    min_risk: Optional[float] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 50
    offset: int = 0
    sort_by: str = "timestamp"
    sort_desc: bool = True

class PaginatedFlows(BaseModel):
    total: int
    flows: List[FlowResponse]
    page: int
    limit: int
