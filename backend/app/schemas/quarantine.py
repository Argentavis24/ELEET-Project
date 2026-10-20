from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

class QuarantineCreate(BaseModel):
    ip_address: str
    reason: str

class QuarantineResponse(BaseModel):
    id: int
    ip_address: str
    reason: str
    blocked_at: datetime
    blocked_by: str
    is_active: bool

    class Config:
        from_attributes = True

class QuarantineListResponse(BaseModel):
    total: int
    blocked_ips: List[QuarantineResponse]
