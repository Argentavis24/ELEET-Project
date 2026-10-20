from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.quarantine import QuarantinedIP
from app.schemas.quarantine import QuarantineCreate, QuarantineResponse, QuarantineListResponse
from app.engine.detector import nids_engine

router = APIRouter(prefix="/quarantine", tags=["IP Quarantine"])

@router.get("", response_model=QuarantineListResponse)
def list_quarantined_ips(db: Session = Depends(get_db)):
    blocks = db.query(QuarantinedIP).filter(QuarantinedIP.is_active == True).all()
    return QuarantineListResponse(
        total=len(blocks),
        blocked_ips=blocks
    )

@router.post("", response_model=QuarantineResponse)
def block_ip(block_in: QuarantineCreate, db: Session = Depends(get_db)):
    existing = db.query(QuarantinedIP).filter(QuarantinedIP.ip_address == block_in.ip_address).first()
    if existing:
        existing.is_active = True
        existing.reason = block_in.reason
        db.commit()
        db.refresh(existing)
        nids_engine.add_quarantine(block_in.ip_address)
        return existing
    
    new_block = QuarantinedIP(
        ip_address=block_in.ip_address,
        reason=block_in.reason,
        blocked_by="Analyst",
        is_active=True
    )
    db.add(new_block)
    db.commit()
    db.refresh(new_block)
    nids_engine.add_quarantine(block_in.ip_address)
    return new_block

@router.delete("/{ip_address}")
def unblock_ip(ip_address: str, db: Session = Depends(get_db)):
    existing = db.query(QuarantinedIP).filter(QuarantinedIP.ip_address == ip_address).first()
    if not existing:
        raise HTTPException(status_code=404, detail=f"IP {ip_address} not found in quarantine")
    
    existing.is_active = False
    db.commit()
    nids_engine.remove_quarantine(ip_address)
    return {
        "status": "success",
        "message": f"IP {ip_address} released from active quarantine"
    }
