import asyncio
import json
from contextlib import asynccontextmanager
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.api.v1 import api_router
from app.seed import seed_database
from app.engine.detector import nids_engine
from app.simulation.traffic_generator import traffic_generator
from app.models.flow import NetworkFlow
from app.models.alert import Alert

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        message_str = json.dumps(message, default=str)
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message_str)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)

ws_manager = ConnectionManager()

# Background flow processor callback for simulated traffic
async def handle_simulated_flow(flow_in):
    # Process with engine in database session
    db = SessionLocal()
    try:
        flow, alert = nids_engine.process_flow(flow_in, db)
        
        flow_data = {
            "id": flow.id,
            "timestamp": flow.timestamp.isoformat(),
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "duration": flow.duration,
            "classification": flow.classification,
            "risk_score": flow.risk_score,
            "alert_reason": flow.alert_reason,
            "mac_address": flow.mac_address,
            "is_simulated": flow.is_simulated
        }

        # Broadcast flow
        await ws_manager.broadcast({
            "type": "FLOW",
            "data": flow_data
        })

        # Broadcast alert if triggered
        if alert:
            traffic_generator.total_simulated_alerts += 1
            alert_data = {
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "protocol": alert.protocol,
                "evidence": alert.evidence,
                "explanation": alert.explanation,
                "recommended_action": alert.recommended_action,
                "status": alert.status,
                "notes": alert.notes,
                "flow_id": alert.flow_id,
                "updated_at": alert.updated_at.isoformat()
            }
            await ws_manager.broadcast({
                "type": "ALERT",
                "data": alert_data
            })
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables and seed DB
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()

    # Wire simulation callback
    traffic_generator.set_callback(handle_simulated_flow)
    # Start traffic simulation in background
    traffic_generator.start()

    yield

    # Shutdown
    traffic_generator.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="CyberDefend Network Intrusion Detection System (NIDS) REST & WebSocket API",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "active_ws_clients": len(ws_manager.active_connections)
    }

# WebSocket Endpoints (support both /ws and /api/v1/ws)
@app.websocket("/ws")
@app.websocket(f"{settings.API_V1_STR}/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial welcome and ping
        await websocket.send_text(json.dumps({
            "type": "CONNECTED",
            "message": "Connected to NIDS Real-Time Threat Stream"
        }))
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                # Handle client actions like ping or rate tuning
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Static Files (Production UI mount)
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../frontend/dist"))
if not os.path.exists(frontend_dist):
    frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend/dist"))

if os.path.exists(frontend_dist) and os.path.exists(os.path.join(frontend_dist, "index.html")):
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Don't intercept API or WS paths
        if full_path.startswith("api") or full_path.startswith("ws") or full_path.startswith("health"):
            return None
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
