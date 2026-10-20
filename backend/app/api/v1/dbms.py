import os
import sqlite3
import json
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.database import get_db, SessionLocal
from app.core.config import settings
from app.models.flow import NetworkFlow
from app.models.alert import Alert
from app.schemas.flow import FlowCreate
from app.engine.detector import nids_engine

router = APIRouter(prefix="/dbms", tags=["Database Scanner & DBMS"])

UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../data/uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Helper to inspect an external SQLite database
def inspect_sqlite_db(file_path: str) -> Dict[str, Any]:
    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    try:
        # Get all user tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [row[0] for row in cursor.fetchall()]
        
        table_details = {}
        for tbl in tables:
            cursor.execute(f"PRAGMA table_info('{tbl}');")
            columns = [
                {"cid": col[0], "name": col[1], "type": col[2], "notnull": bool(col[3]), "pk": bool(col[5])}
                for col in cursor.fetchall()
            ]
            cursor.execute(f"SELECT COUNT(*) FROM '{tbl}';")
            row_count = cursor.fetchone()[0]
            
            # Detect probable flow columns
            col_names = [c["name"].lower() for c in columns]
            probable_mapping = {
                "src_ip": next((c["name"] for c in columns if c["name"].lower() in ["src_ip", "source_ip", "source", "src", "client_ip"]), None),
                "dst_ip": next((c["name"] for c in columns if c["name"].lower() in ["dst_ip", "dest_ip", "destination_ip", "dest", "target_ip", "server_ip"]), None),
                "src_port": next((c["name"] for c in columns if c["name"].lower() in ["src_port", "source_port", "sport"]), None),
                "dst_port": next((c["name"] for c in columns if c["name"].lower() in ["dst_port", "dest_port", "port", "dport", "target_port"]), None),
                "protocol": next((c["name"] for c in columns if c["name"].lower() in ["protocol", "proto"]), None),
                "packet_count": next((c["name"] for c in columns if c["name"].lower() in ["packet_count", "packets", "pkts", "count"]), None),
                "byte_count": next((c["name"] for c in columns if c["name"].lower() in ["byte_count", "bytes", "length", "size", "octets"]), None),
                "duration": next((c["name"] for c in columns if c["name"].lower() in ["duration", "dur", "time_taken", "elapsed"]), None),
                "timestamp": next((c["name"] for c in columns if c["name"].lower() in ["timestamp", "time", "date", "created_at"]), None),
            }
            
            table_details[tbl] = {
                "columns": columns,
                "row_count": row_count,
                "probable_mapping": probable_mapping
            }
        return {"tables": table_details}
    finally:
        conn.close()

@router.get("/databases")
def list_uploaded_databases():
    """List all database files available in the uploads directory"""
    files = []
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            if f.endswith(('.db', '.sqlite', '.sqlite3')):
                fp = os.path.join(UPLOAD_DIR, f)
                stat = os.stat(fp)
                files.append({
                    "filename": f,
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                    "file_path": fp
                })
    return {"databases": sorted(files, key=lambda x: x["created_at"], reverse=True)}

@router.post("/upload")
async def upload_database_file(file: UploadFile = File(...)):
    """Upload an external SQLite database file for security scanning"""
    if not file.filename.lower().endswith(('.db', '.sqlite', '.sqlite3')):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload a SQLite database file (.db, .sqlite, .sqlite3)"
        )

    safe_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        inspection = inspect_sqlite_db(file_path)
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=400, detail=f"Invalid or corrupted SQLite database: {str(e)}")

    return {
        "status": "success",
        "filename": safe_name,
        "original_name": file.filename,
        "file_path": file_path,
        "size_bytes": os.path.getsize(file_path),
        "tables": inspection["tables"]
    }

import uuid

@router.post("/generate-sample")
def generate_sample_database():
    """Generate a realistic external SQLite database file containing enterprise traffic and attacks"""
    sample_filename = f"sample_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.db"
    file_path = os.path.join(UPLOAD_DIR, sample_filename)

    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS external_network_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_count INTEGER,
            byte_count INTEGER,
            duration REAL,
            service_label TEXT
        );
    """)

    now = datetime.now(timezone.utc)
    flows = []

    # 1. Normal traffic (60 records)
    for i in range(60):
        t = (now - timedelta(minutes=60 - i)).isoformat()
        flows.append((t, "10.0.1.15", "142.250.190.46", 45000 + i, 443, "TCP", 14, 8500, 1.25, "Web HTTPS"))
        flows.append((t, "10.0.1.20", "8.8.8.8", 48000 + i, 53, "UDP", 2, 140, 0.05, "DNS Lookup"))

    # 2. Port scan attack on host 10.0.1.50 (9 distinct ports in short order)
    scan_time = (now - timedelta(minutes=25)).isoformat()
    for port in [21, 22, 23, 25, 80, 110, 443, 3306, 8080]:
        flows.append((scan_time, "192.168.100.88", "10.0.1.50", 52000, port, "TCP", 1, 64, 0.01, "Port Recon Probe"))

    # 3. SSH Brute Force against 10.0.1.10:22 (6 rapid attempts)
    bf_time = (now - timedelta(minutes=18)).isoformat()
    for _ in range(6):
        flows.append((bf_time, "192.168.100.105", "10.0.1.10", 54100, 22, "TCP", 6, 420, 0.35, "SSH Login Attempt"))

    # 4. Volumetric DDoS Flood towards 10.0.1.5:80 (high packet counts)
    flood_time = (now - timedelta(minutes=10)).isoformat()
    for _ in range(15):
        flows.append((flood_time, "172.16.50.99", "10.0.1.5", 39000, 80, "TCP", 350, 210000, 0.02, "HTTP Flood"))

    # 5. Metasploit Trojan Outbound Exfiltration (Port 4444, 7MB payload)
    exfil_time = (now - timedelta(minutes=5)).isoformat()
    flows.append((exfil_time, "10.0.1.33", "198.51.100.77", 49200, 4444, "TCP", 2200, 7800000, 4.8, "C2 Meterpreter"))

    # 6. Malicious threat actor C2 beacon
    c2_time = (now - timedelta(minutes=2)).isoformat()
    flows.append((c2_time, "185.220.101.5", "10.0.1.25", 58900, 9001, "TCP", 20, 3200, 0.8, "Known Tor C2"))

    cursor.executemany("""
        INSERT INTO external_network_traffic 
        (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, duration, service_label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, flows)

    conn.commit()
    conn.close()

    inspection = inspect_sqlite_db(file_path)
    return {
        "status": "success",
        "message": "Sample network telemetry database generated successfully",
        "filename": sample_filename,
        "file_path": file_path,
        "size_bytes": os.path.getsize(file_path),
        "tables": inspection["tables"]
    }

@router.post("/scan")
def scan_database(
    filename: str = Form(...),
    table_name: str = Form(...),
    protocol_filter: Optional[str] = Form(None),
    min_packets: Optional[int] = Form(None),
    min_bytes: Optional[int] = Form(None),
    port_filter: Optional[int] = Form(None),
    ip_filter: Optional[str] = Form(None),
    time_window_minutes: Optional[int] = Form(None),
    limit: int = Form(1000),
    db: Session = Depends(get_db)
):
    """
    Scans rows of an external database table through the NIDS detection engine (heuristics + ML Isolation Forest).
    Returns a comprehensive forensic security scan report with identified threats.
    """
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Database file '{filename}' not found in uploads")

    conn = sqlite3.connect(file_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Inspect columns
        cursor.execute(f"PRAGMA table_info('{table_name}');")
        col_list = [row[1] for row in cursor.fetchall()]
        if not col_list:
            raise HTTPException(status_code=400, detail=f"Table '{table_name}' does not exist in database")

        # Build dynamic query
        query = f"SELECT * FROM '{table_name}' WHERE 1=1"
        params = []

        # Find columns
        def find_col(aliases):
            for a in aliases:
                for c in col_list:
                    if c.lower() == a:
                        return c
            return None

        c_proto = find_col(["protocol", "proto"])
        c_port = find_col(["dst_port", "dest_port", "port", "dport"])
        c_pkts = find_col(["packet_count", "packets", "pkts"])
        c_bytes = find_col(["byte_count", "bytes", "size", "length"])
        c_src = find_col(["src_ip", "source_ip", "src", "source"])
        c_dst = find_col(["dst_ip", "dest_ip", "dst", "dest", "target_ip"])
        c_time = find_col(["timestamp", "time", "date"])

        if protocol_filter and c_proto:
            query += f" AND {c_proto} = ?"
            params.append(protocol_filter.upper())
        if port_filter and c_port:
            query += f" AND {c_port} = ?"
            params.append(port_filter)
        if min_packets and c_pkts:
            query += f" AND {c_pkts} >= ?"
            params.append(min_packets)
        if min_bytes and c_bytes:
            query += f" AND {c_bytes} >= ?"
            params.append(min_bytes)
        if ip_filter:
            conds = []
            if c_src:
                conds.append(f"{c_src} LIKE ?")
                params.append(f"%{ip_filter}%")
            if c_dst:
                conds.append(f"{c_dst} LIKE ?")
                params.append(f"%{ip_filter}%")
            if conds:
                query += f" AND ({' OR '.join(conds)})"

        query += f" LIMIT {limit}"
        cursor.execute(query, params)
        rows = cursor.fetchall()

    finally:
        conn.close()

    # Pass rows through the NIDS detection engine
    scanned_flows = []
    threat_findings = []
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    category_counts = {}

    for row in rows:
        r_dict = dict(row)
        
        # Extract normalized attributes
        src_ip = str(r_dict.get(c_src or "src_ip") or "192.168.1.100")
        dst_ip = str(r_dict.get(c_dst or "dst_ip") or "10.0.0.1")
        try:
            src_port = int(r_dict.get("src_port", 40000))
        except:
            src_port = 40000
        try:
            dst_port = int(r_dict.get(c_port or "dst_port", 80))
        except:
            dst_port = 80
        proto = str(r_dict.get(c_proto or "protocol") or "TCP").upper()
        try:
            packets = int(r_dict.get(c_pkts or "packet_count", 1))
        except:
            packets = 1
        try:
            bytes_val = int(r_dict.get(c_bytes or "byte_count", 64))
        except:
            bytes_val = 64
        try:
            duration = float(r_dict.get("duration", 0.1))
        except:
            duration = 0.1

        ts_raw = r_dict.get(c_time or "timestamp")
        try:
            ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now(timezone.utc)
        except:
            ts = datetime.now(timezone.utc)

        flow_in = FlowCreate(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            packet_count=packets,
            byte_count=bytes_val,
            duration=duration,
            is_simulated=False
        )

        # Temporary in-memory evaluation against NIDS engine rules & ML model
        # 1. Check rules
        current_ts = ts.timestamp()
        nids_engine.window.add_flow(
            current_ts, src_ip, dst_ip, src_port, dst_port, proto, packets, bytes_val
        )

        matched_candidate = None
        for rule in nids_engine.rules:
            cand = rule.evaluate(flow_in, nids_engine.window, current_ts)
            if cand:
                matched_candidate = cand
                break

        # 2. If no heuristic, check ML model
        if not matched_candidate:
            ml_cand = nids_engine.ml_detector.evaluate(flow_in)
            if ml_cand:
                matched_candidate = ml_cand

        if matched_candidate:
            classification = matched_candidate.classification
            risk_score = matched_candidate.risk_score
            sev = matched_candidate.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[classification] = category_counts.get(classification, 0) + 1

            threat_findings.append({
                "rule_name": matched_candidate.rule_name,
                "severity": sev,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "classification": classification,
                "risk_score": risk_score,
                "explanation": matched_candidate.explanation,
                "recommended_action": matched_candidate.recommended_action,
                "timestamp": ts.isoformat()
            })
        else:
            ml_score, _, _ = nids_engine.ml_detector.score_flow(flow_in)
            classification = "Normal"
            risk_score = round(ml_score * 0.35, 2)

        scanned_flows.append({
            "timestamp": ts.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "packet_count": packets,
            "byte_count": bytes_val,
            "duration": duration,
            "classification": classification,
            "risk_score": risk_score
        })

    return {
        "status": "success",
        "scanned_database": filename,
        "table_name": table_name,
        "total_rows_scanned": len(scanned_flows),
        "threats_detected_count": len(threat_findings),
        "severity_summary": severity_counts,
        "classification_summary": category_counts,
        "threat_findings": threat_findings[:150],  # top findings
        "scanned_flows_sample": scanned_flows[:50]
    }

@router.post("/attach")
def attach_and_merge_database(
    filename: str = Form(...),
    table_name: str = Form(...),
    import_threats_only: bool = Form(False),
    db: Session = Depends(get_db)
):
    """
    Attaches the scanned database and merges its telemetry flows and security alerts into 
    the active primary NIDS database so they appear in live dashboards, charts, and SOC queues.
    """
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Database file not found")

    conn = sqlite3.connect(file_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute(f"SELECT * FROM '{table_name}';")
        rows = cursor.fetchall()
        cursor.execute(f"PRAGMA table_info('{table_name}');")
        col_list = [r[1] for r in cursor.fetchall()]
    finally:
        conn.close()

    def find_col(aliases):
        for a in aliases:
            for c in col_list:
                if c.lower() == a:
                    return c
        return None

    c_proto = find_col(["protocol", "proto"])
    c_port = find_col(["dst_port", "dest_port", "port", "dport"])
    c_pkts = find_col(["packet_count", "packets", "pkts"])
    c_bytes = find_col(["byte_count", "bytes", "size", "length"])
    c_src = find_col(["src_ip", "source_ip", "src", "source"])
    c_dst = find_col(["dst_ip", "dest_ip", "dst", "dest", "target_ip"])
    c_time = find_col(["timestamp", "time", "date"])

    imported_flows_count = 0
    imported_alerts_count = 0

    for row in rows:
        r_dict = dict(row)
        src_ip = str(r_dict.get(c_src or "src_ip") or "192.168.1.100")
        dst_ip = str(r_dict.get(c_dst or "dst_ip") or "10.0.0.1")
        try:
            src_port = int(r_dict.get("src_port", 40000))
        except:
            src_port = 40000
        try:
            dst_port = int(r_dict.get(c_port or "dst_port", 80))
        except:
            dst_port = 80
        proto = str(r_dict.get(c_proto or "protocol") or "TCP").upper()
        try:
            packets = int(r_dict.get(c_pkts or "packet_count", 1))
        except:
            packets = 1
        try:
            bytes_val = int(r_dict.get(c_bytes or "byte_count", 64))
        except:
            bytes_val = 64
        try:
            duration = float(r_dict.get("duration", 0.1))
        except:
            duration = 0.1

        ts_raw = r_dict.get(c_time or "timestamp")
        try:
            ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now(timezone.utc)
        except:
            ts = datetime.now(timezone.utc)

        flow_in = FlowCreate(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            packet_count=packets,
            byte_count=bytes_val,
            duration=duration,
            is_simulated=False
        )

        # Process with live engine and persist to active primary DB
        flow, alert = nids_engine.process_flow(flow_in, db)
        if alert:
            imported_alerts_count += 1
        imported_flows_count += 1

    return {
        "status": "success",
        "message": f"Successfully attached and merged {imported_flows_count} flows and {imported_alerts_count} security alerts into primary NIDS DBMS.",
        "imported_flows": imported_flows_count,
        "imported_alerts": imported_alerts_count,
        "attached_database": filename
    }
