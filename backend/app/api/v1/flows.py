import csv
import io
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, or_
from app.core.database import get_db
from app.models.flow import NetworkFlow
from app.schemas.flow import FlowCreate, FlowResponse, PaginatedFlows
from app.engine.detector import nids_engine

router = APIRouter(prefix="/flows", tags=["Network Flows"])

@router.get("", response_model=PaginatedFlows)
def get_flows(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    classification: Optional[str] = None,
    min_risk: Optional[float] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort_by: str = "timestamp",
    sort_desc: bool = True,
    db: Session = Depends(get_db)
):
    query = db.query(NetworkFlow)

    if src_ip:
        query = query.filter(NetworkFlow.src_ip.like(f"%{src_ip}%"))
    if dst_ip:
        query = query.filter(NetworkFlow.dst_ip.like(f"%{dst_ip}%"))
    if port:
        query = query.filter(or_(NetworkFlow.src_port == port, NetworkFlow.dst_port == port))
    if protocol:
        query = query.filter(NetworkFlow.protocol == protocol.upper())
    if classification:
        query = query.filter(NetworkFlow.classification == classification)
    if min_risk is not None:
        query = query.filter(NetworkFlow.risk_score >= min_risk)
    if search:
        s = f"%{search}%"
        query = query.filter(or_(
            NetworkFlow.src_ip.like(s),
            NetworkFlow.dst_ip.like(s),
            NetworkFlow.classification.like(s),
            NetworkFlow.alert_reason.like(s)
        ))

    total = query.count()

    # Sorting
    sort_column = getattr(NetworkFlow, sort_by, NetworkFlow.timestamp)
    query = query.order_by(desc(sort_column) if sort_desc else asc(sort_column))

    flows = query.offset(offset).limit(limit).all()

    return PaginatedFlows(
        total=total,
        flows=flows,
        page=(offset // limit) + 1,
        limit=limit
    )

@router.get("/export")
def export_flows_csv(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    classification: Optional[str] = None,
    min_risk: Optional[float] = None,
    limit: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(get_db)
):
    query = db.query(NetworkFlow)

    if src_ip:
        query = query.filter(NetworkFlow.src_ip.like(f"%{src_ip}%"))
    if dst_ip:
        query = query.filter(NetworkFlow.dst_ip.like(f"%{dst_ip}%"))
    if port:
        query = query.filter(or_(NetworkFlow.src_port == port, NetworkFlow.dst_port == port))
    if protocol:
        query = query.filter(NetworkFlow.protocol == protocol.upper())
    if classification:
        query = query.filter(NetworkFlow.classification == classification)
    if min_risk is not None:
        query = query.filter(NetworkFlow.risk_score >= min_risk)

    flows = query.order_by(desc(NetworkFlow.timestamp)).limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp (UTC)", "Source IP", "Destination IP", "Source Port", 
        "Destination Port", "Protocol", "Packets", "Bytes", "Duration (s)", 
        "Classification", "Risk Score", "Alert Reason", "MAC Address", "Simulated"
    ])

    for f in flows:
        writer.writerow([
            f.id,
            f.timestamp.isoformat(),
            f.src_ip,
            f.dst_ip,
            f.src_port,
            f.dst_port,
            f.protocol,
            f.packet_count,
            f.byte_count,
            f.duration,
            f.classification,
            f.risk_score,
            f.alert_reason or "",
            f.mac_address or "",
            f.is_simulated
        ])

    csv_data = output.getvalue()
    output.close()

    filename = f"network_flows_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/ingest", response_model=FlowResponse)
def ingest_flow(flow_in: FlowCreate, db: Session = Depends(get_db)):
    flow, alert = nids_engine.process_flow(flow_in, db)
    return flow
