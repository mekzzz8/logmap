import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

WINDOWS_LOG = """
EventID=4625
Date/Time=2024-01-15T10:20:00Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4625
Date/Time=2024-01-15T10:20:05Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4625
Date/Time=2024-01-15T10:20:10Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4625
Date/Time=2024-01-15T10:20:15Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4625
Date/Time=2024-01-15T10:20:20Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3

EventID=4624
Date/Time=2024-01-15T10:25:00Z
Account Name=administrator
Account Domain=CORP
Source Network Address=192.168.1.45
Logon Type=3
"""


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ingest():
    r = client.post("/api/ingest", json={"raw_logs": WINDOWS_LOG, "filename": "test.log"})
    assert r.status_code == 200
    data = r.json()
    assert "session_id" in data
    assert data["total_events"] >= 6
    assert data["risk_score"] > 0
    return data["session_id"]


def test_ingest_empty():
    r = client.post("/api/ingest", json={"raw_logs": "   ", "filename": "empty.log"})
    assert r.status_code == 400


def test_graph_endpoint():
    sid = test_ingest()
    r = client.get(f"/api/graph/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data and "edges" in data
    assert len(data["nodes"]) > 0


def test_timeline_endpoint():
    sid = test_ingest()
    r = client.get(f"/api/timeline/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert data["total"] >= 6


def test_risk_endpoint():
    sid = test_ingest()
    r = client.get(f"/api/risk/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert "global_score" in data
    assert "risk_level" in data
    assert "technique_scores" in data
    assert "patterns" in data


def test_not_found():
    r = client.get("/api/graph/nonexistent-id")
    assert r.status_code == 404


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
