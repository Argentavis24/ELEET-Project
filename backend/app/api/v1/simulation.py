from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db, SessionLocal
from app.simulation.traffic_generator import traffic_generator
from app.schemas.simulation import SimulationConfig, SimulationStatus, TriggerAttackRequest
from app.engine.detector import nids_engine

router = APIRouter(prefix="/simulation", tags=["Traffic Simulation"])

@router.get("/status", response_model=SimulationStatus)
def get_simulation_status():
    return SimulationStatus(
        is_running=traffic_generator.is_running,
        rate_flows_per_second=traffic_generator.rate_flows_per_second,
        attack_probability=traffic_generator.attack_probability,
        total_simulated_flows=traffic_generator.total_simulated_flows,
        total_simulated_alerts=traffic_generator.total_simulated_alerts,
        active_scenarios=traffic_generator.active_scenarios
    )

@router.post("/start", response_model=SimulationStatus)
def start_simulation():
    traffic_generator.start()
    return get_simulation_status()

@router.post("/stop", response_model=SimulationStatus)
def stop_simulation():
    traffic_generator.stop()
    return get_simulation_status()

@router.post("/configure", response_model=SimulationStatus)
def configure_simulation(config: SimulationConfig):
    traffic_generator.rate_flows_per_second = config.rate_flows_per_second
    traffic_generator.attack_probability = config.attack_probability
    traffic_generator.active_scenarios = config.active_scenarios
    if config.is_running and not traffic_generator.is_running:
        traffic_generator.start()
    elif not config.is_running and traffic_generator.is_running:
        traffic_generator.stop()
    return get_simulation_status()

@router.post("/trigger")
def trigger_attack_scenario(req: TriggerAttackRequest, db: Session = Depends(get_db)):
    valid_scenarios = [
        "port_scan", "brute_force", "ddos_flood", 
        "suspicious_outbound", "arp_spoof", "blacklist_comm"
    ]
    if req.scenario not in valid_scenarios:
        raise HTTPException(
            status_code=400, 
            detail=f"Unknown scenario '{req.scenario}'. Allowed: {', '.join(valid_scenarios)}"
        )

    flows = traffic_generator.trigger_scenario(req.scenario, req.target_ip)
    processed_alerts = []
    
    for f in flows:
        flow, alert = nids_engine.process_flow(f, db)
        if alert:
            processed_alerts.append({
                "alert_id": alert.id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "explanation": alert.explanation
            })

    return {
        "status": "success",
        "scenario": req.scenario,
        "flows_generated": len(flows),
        "alerts_triggered": len(processed_alerts),
        "alerts": processed_alerts
    }
