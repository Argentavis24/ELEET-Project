import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.seed import seed_database

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

def test_auth_login_and_token():
    with TestClient(app) as client:
        response = client.post(
            f"{settings.API_V1_STR}/auth/login",
            json={"username": "admin", "password": "CyberDefense2026!"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        token = data["access_token"]

        # Verify /me endpoint
        headers = {"Authorization": f"Bearer {token}"}
        me_resp = client.get(f"{settings.API_V1_STR}/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["username"] == "admin"

def test_dashboard_metrics_and_charts():
    with TestClient(app) as client:
        # Metrics
        resp = client.get(f"{settings.API_V1_STR}/dashboard/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_flows" in data
        assert "active_alerts" in data
        assert "throughput_kbps" in data

        # Charts
        chart_resp = client.get(f"{settings.API_V1_STR}/dashboard/charts")
        assert chart_resp.status_code == 200
        chart_data = chart_resp.json()
        assert "protocol_distribution" in chart_data
        assert "alert_severity" in chart_data
        assert "traffic_over_time" in chart_data

def test_flows_query_and_export():
    with TestClient(app) as client:
        # Query flows
        resp = client.get(f"{settings.API_V1_STR}/flows?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert "flows" in data
        assert "total" in data

        # CSV Export
        csv_resp = client.get(f"{settings.API_V1_STR}/flows/export?limit=5")
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]
        assert "Timestamp (UTC)" in csv_resp.text

def test_alerts_query_and_patch():
    with TestClient(app) as client:
        resp = client.get(f"{settings.API_V1_STR}/alerts?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data
        
        if data["alerts"]:
            first_alert = data["alerts"][0]
            alert_id = first_alert["id"]

            # Patch status and add analyst note
            patch_resp = client.patch(
                f"{settings.API_V1_STR}/alerts/{alert_id}",
                json={"status": "INVESTIGATING", "notes": "SOC Analyst reviewing packet payload"}
            )
            assert patch_resp.status_code == 200
            updated = patch_resp.json()
            assert updated["status"] == "INVESTIGATING"
            assert "SOC Analyst reviewing" in updated["notes"]

def test_quarantine_block_and_unblock():
    with TestClient(app) as client:
        target_ip = "192.0.2.123"

        # Block IP
        block_resp = client.post(
            f"{settings.API_V1_STR}/quarantine",
            json={"ip_address": target_ip, "reason": "Test quarantine action"}
        )
        assert block_resp.status_code == 200
        assert block_resp.json()["ip_address"] == target_ip
        assert block_resp.json()["is_active"] == True

        # Check list
        list_resp = client.get(f"{settings.API_V1_STR}/quarantine")
        assert list_resp.status_code == 200
        ips = [b["ip_address"] for b in list_resp.json()["blocked_ips"]]
        assert target_ip in ips

        # Unblock IP
        del_resp = client.delete(f"{settings.API_V1_STR}/quarantine/{target_ip}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "success"

def test_simulation_trigger():
    with TestClient(app) as client:
        resp = client.post(
            f"{settings.API_V1_STR}/simulation/trigger",
            json={"scenario": "port_scan", "intensity": 5}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["flows_generated"] >= 5
