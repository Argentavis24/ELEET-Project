from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from app.core.database import get_db
from app.models.alert import Alert
from app.models.quarantine import QuarantinedIP
from app.schemas.alert import AlertResponse, AlertUpdate, PaginatedAlerts
from app.engine.detector import nids_engine

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

@router.get("", response_model=PaginatedAlerts)
def get_alerts(
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    rule_name: Optional[str] = None,
    src_ip: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status_filter:
        query = query.filter(Alert.status == status_filter.upper())
    if rule_name:
        query = query.filter(Alert.rule_name == rule_name)
    if src_ip:
        query = query.filter(Alert.src_ip.like(f"%{src_ip}%"))
    if search:
        s = f"%{search}%"
        query = query.filter(or_(
            Alert.src_ip.like(s),
            Alert.dst_ip.like(s),
            Alert.rule_name.like(s),
            Alert.explanation.like(s),
            Alert.notes.like(s)
        ))

    total = query.count()
    alerts = query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit).all()

    return PaginatedAlerts(
        total=total,
        alerts=alerts,
        page=(offset // limit) + 1,
        limit=limit
    )

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, update_data: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update_data.status:
        valid_statuses = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        status_upper = update_data.status.upper()
        if status_upper not in valid_statuses:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
        alert.status = status_upper

    if update_data.notes is not None:
        alert.notes = update_data.notes

    alert.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/quarantine")
def quarantine_alert_source(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    existing = db.query(QuarantinedIP).filter(QuarantinedIP.ip_address == alert.src_ip).first()
    if existing:
        existing.is_active = True
        existing.reason = f"Quarantined from Alert #{alert.id} ({alert.rule_name})"
    else:
        new_block = QuarantinedIP(
            ip_address=alert.src_ip,
            reason=f"Quarantined from Alert #{alert.id} ({alert.rule_name})",
            blocked_by="Analyst",
            is_active=True
        )
        db.add(new_block)

    # Also update alert status to INVESTIGATING
    if alert.status == "NEW":
        alert.status = "INVESTIGATING"

    db.commit()
    nids_engine.add_quarantine(alert.src_ip)

    return {
        "status": "success",
        "message": f"IP {alert.src_ip} has been added to active quarantine",
        "ip_address": alert.src_ip
    }
