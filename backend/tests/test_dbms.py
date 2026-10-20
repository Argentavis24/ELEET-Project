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

def test_dbms_generate_sample_and_list():
    with TestClient(app) as client:
        # Generate sample database
        gen_resp = client.post(f"{settings.API_V1_STR}/dbms/generate-sample")
        assert gen_resp.status_code == 200
        data = gen_resp.json()
        assert data["status"] == "success"
        assert "filename" in data
        assert "external_network_traffic" in data["tables"]
        filename = data["filename"]

        # List uploaded databases
        list_resp = client.get(f"{settings.API_V1_STR}/dbms/databases")
        assert list_resp.status_code == 200
        filenames = [d["filename"] for d in list_resp.json()["databases"]]
        assert filename in filenames

def test_dbms_scan_with_filters():
    with TestClient(app) as client:
        # Generate fresh sample
        gen_resp = client.post(f"{settings.API_V1_STR}/dbms/generate-sample")
        filename = gen_resp.json()["filename"]

        # Scan table
        scan_resp = client.post(
            f"{settings.API_V1_STR}/dbms/scan",
            data={
                "filename": filename,
                "table_name": "external_network_traffic"
            }
        )
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["status"] == "success"
        assert scan_data["total_rows_scanned"] > 50
        assert scan_data["threats_detected_count"] > 0
        assert "Critical" in scan_data["severity_summary"]
        assert len(scan_data["threat_findings"]) > 0

        # Scan with protocol filter
        scan_filtered = client.post(
            f"{settings.API_V1_STR}/dbms/scan",
            data={
                "filename": filename,
                "table_name": "external_network_traffic",
                "protocol_filter": "UDP"
            }
        )
        assert scan_filtered.status_code == 200
        udp_data = scan_filtered.json()
        for f in udp_data["scanned_flows_sample"]:
            assert f["protocol"] == "UDP"

def test_dbms_attach_and_merge():
    with TestClient(app) as client:
        # Generate fresh sample
        gen_resp = client.post(f"{settings.API_V1_STR}/dbms/generate-sample")
        filename = gen_resp.json()["filename"]

        # Attach and merge to active DBMS
        attach_resp = client.post(
            f"{settings.API_V1_STR}/dbms/attach",
            data={
                "filename": filename,
                "table_name": "external_network_traffic"
            }
        )
        assert attach_resp.status_code == 200
        attach_data = attach_resp.json()
        assert attach_data["status"] == "success"
        assert attach_data["imported_flows"] > 0
        assert attach_data["attached_database"] == filename
