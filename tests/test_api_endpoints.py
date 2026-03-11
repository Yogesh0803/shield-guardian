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
from app.middleware.auth import get_current_user
from app.models.user import User
from app.services.enforcer import enforcer

# ------------------------------------------------------------------
# Test DB fixtures
# ------------------------------------------------------------------
TEST_DB_PATH = os.path.abspath("test_guardian_shield.db")
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()

client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    import pathlib
    for name in (TEST_DB_PATH, f"{TEST_DB_PATH}-shm", f"{TEST_DB_PATH}-wal"):
        p = pathlib.Path(name)
        try:
            p.unlink(missing_ok=True)
        except PermissionError:
            pass


@pytest.fixture(autouse=True)
def apply_db_override():
    previous_db_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    yield
    if previous_db_override is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = previous_db_override


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


@pytest.fixture
def policy_auth_override():
    previous_db_override = app.dependency_overrides.get(get_db)
    previous_user_override = app.dependency_overrides.get(get_current_user)
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: User(
        id="policy-test-user",
        email="policytester@example.com",
        hashed_password="hashed",
        name="Policy Tester",
        role="admin",
    )
    try:
        yield {"Authorization": "Bearer policy-test-token"}
    finally:
        if previous_db_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_db_override
        if previous_user_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = previous_user_override


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


class TestPolicyNLPWorkflow:
    """Policy parsing and natural-language policy creation."""

    def test_parse_youtube_schedule_policy(self, policy_auth_override):
        resp = client.post(
            "/api/policies/parse",
            json={"input": "Block YouTube from 9 PM to 6 AM"},
            headers=policy_auth_override,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["purpose"] == "block"
        assert "youtube.com" in data["parsed"]["domains"]
        assert "googlevideo.com" in data["parsed"]["domains"]
        assert data["parsed"]["time_range"] == {"start": "21:00", "end": "06:00"}

    def test_create_policy_from_natural_language_only(self, policy_auth_override):
        resp = client.post(
            "/api/policies",
            json={
                "name": "Sleep YouTube Block",
                "natural_language": "Block YouTube from 9 PM to 6 AM",
                "is_active": True,
            },
            headers=policy_auth_override,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["purpose"] == "block"
        assert "youtube.com" in data["conditions"]["domains"]
        assert data["conditions"]["time_range"] == {"start": "21:00", "end": "06:00"}


class TestPolicyToggleWorkflow:
    """Policy activation state can be toggled without deleting the policy."""

    def test_toggle_policy_flips_is_active(self, policy_auth_override, monkeypatch):
        monkeypatch.setattr(
            enforcer,
            "enforce_policy",
            lambda policy_id, purpose, conditions: {"status": "enforced", "enforced": True},
        )
        monkeypatch.setattr(
            enforcer,
            "unenforce_policy",
            lambda policy_id: {"status": "unenforced"},
        )

        create_resp = client.post(
            "/api/policies",
            json={
                "name": "Toggle Me",
                "purpose": "monitor",
                "conditions": {"domains": ["example.com"]},
                "is_active": True,
            },
            headers=policy_auth_override,
        )
        assert create_resp.status_code == 200
        policy = create_resp.json()
        assert policy["is_active"] is True

        toggle_off_resp = client.patch(
            f"/api/policies/{policy['id']}/toggle",
            json={},
            headers=policy_auth_override,
        )
        assert toggle_off_resp.status_code == 200
        assert toggle_off_resp.json()["is_active"] is False

        toggle_on_resp = client.patch(
            f"/api/policies/{policy['id']}/toggle",
            json={},
            headers=policy_auth_override,
        )
        assert toggle_on_resp.status_code == 200
        assert toggle_on_resp.json()["is_active"] is True
