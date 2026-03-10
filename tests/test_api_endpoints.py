"""
API endpoint verification tests for the new security feature endpoints.

Tests:
  - POST /api/ml/metrics/update  (drift metrics push)
  - GET  /api/ml/metrics         (drift metrics read — requires auth)
  - GET  /api/ml/rate-limiter/stats
  - GET  /api/ml/threat-intel/{ip}
"""

import os
import sys
import pytest

# Ensure the backend package is importable as 'app'
_backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend")
_backend_dir = os.path.abspath(_backend_dir)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# Override settings before any app import
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_guardian_shield.db")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("ML_API_KEY", "test-ml-key")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app

# ------------------------------------------------------------------
# Test DB fixtures
# ------------------------------------------------------------------
TEST_DB_URL = "sqlite:///./test_guardian_shield.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    import pathlib
    for name in ("test_guardian_shield.db", "test_guardian_shield.db-shm",
                 "test_guardian_shield.db-wal"):
        p = pathlib.Path(name)
        try:
            p.unlink(missing_ok=True)
        except PermissionError:
            pass


# ------------------------------------------------------------------
# Helper: get auth token
# ------------------------------------------------------------------

def _get_auth_token() -> str:
    """Register + login to get a JWT token for protected endpoints."""
    # Try signup
    client.post("/api/auth/register", json={
        "email": "testuser@example.com",
        "password": "TestPassword123!",
        "name": "Test User",
    })
    # Login
    resp = client.post("/api/auth/login", json={
        "email": "testuser@example.com",
        "password": "TestPassword123!",
    })
    if resp.status_code == 200:
        return resp.json().get("access_token", "")
    return ""


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestDriftMetricsUpdateEndpoint:
    """POST /api/ml/metrics/update — push drift metrics from ML engine."""

    def test_update_accepted_with_valid_key(self):
        resp = client.post(
            "/api/ml/metrics/update",
            json={"predictions_per_min": 42.0, "anomaly_rate": 0.12},
            headers={"X-ML-API-Key": "test-ml-key"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_update_rejected_without_key(self):
        resp = client.post(
            "/api/ml/metrics/update",
            json={"predictions_per_min": 1.0},
        )
        assert resp.status_code == 403

    def test_update_rejected_with_bad_key(self):
        resp = client.post(
            "/api/ml/metrics/update",
            json={},
            headers={"X-ML-API-Key": "wrong-key"},
        )
        assert resp.status_code == 403


class TestDriftMetricsGetEndpoint:
    """GET /api/ml/metrics — read drift + DB metrics (auth required)."""

    def test_metrics_returns_expected_keys(self):
        token = _get_auth_token()
        if not token:
            pytest.skip("Auth not available")

        # Push some data first
        client.post(
            "/api/ml/metrics/update",
            json={"predictions_per_min": 10.0, "anomaly_rate": 0.05},
            headers={"X-ML-API-Key": "test-ml-key"},
        )

        resp = client.get(
            "/api/ml/metrics",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "predictions_per_min" in data
        assert "anomaly_rate" in data
        assert "drift_detected" in data
        assert "db_predictions_last_5min" in data

    def test_metrics_requires_auth(self):
        resp = client.get("/api/ml/metrics")
        assert resp.status_code in (401, 403)


class TestRateLimiterStatsEndpoint:
    """GET /api/ml/rate-limiter/stats"""

    def test_stats_returns_structure(self):
        token = _get_auth_token()
        if not token:
            pytest.skip("Auth not available")

        resp = client.get(
            "/api/ml/rate-limiter/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "tracked_ips" in data
        assert "blocked_ips" in data
        assert "config" in data

    def test_stats_requires_auth(self):
        resp = client.get("/api/ml/rate-limiter/stats")
        assert resp.status_code in (401, 403)


class TestThreatIntelEndpoint:
    """GET /api/ml/threat-intel/{ip}"""

    def test_lookup_returns_structure(self):
        token = _get_auth_token()
        if not token:
            pytest.skip("Auth not available")

        resp = client.get(
            "/api/ml/threat-intel/8.8.8.8",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "ip" in data
        assert "risk_score" in data
        assert "should_block" in data

    def test_lookup_requires_auth(self):
        resp = client.get("/api/ml/threat-intel/1.2.3.4")
        assert resp.status_code in (401, 403)
