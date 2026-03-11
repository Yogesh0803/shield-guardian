from datetime import datetime, timedelta, timezone

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.middleware.auth import get_current_user
from app.models.policy import Policy
from app.models.user import User
from app.services.enforcer import enforcer
from ml.enforcer.nlp_parser import NLPPolicyParser


TEST_DB_PATH = os.path.abspath("test_guardian_policy_system.db")
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


def override_current_user():
    return User(
        id="test-user",
        email="policytester@example.com",
        hashed_password="hashed",
        name="Policy Tester",
        role="admin",
    )


client = TestClient(app)


@pytest.fixture(autouse=True, scope="module")
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    for name in (
        TEST_DB_PATH,
        f"{TEST_DB_PATH}-shm",
        f"{TEST_DB_PATH}-wal",
    ):
        try:
            os.remove(name)
        except FileNotFoundError:
            pass
        except PermissionError:
            pass


@pytest.fixture(autouse=True)
def apply_overrides():
    previous_db_override = app.dependency_overrides.get(get_db)
    previous_user_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_current_user
    yield
    if previous_db_override is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = previous_db_override
    if previous_user_override is None:
        app.dependency_overrides.pop(get_current_user, None)
    else:
        app.dependency_overrides[get_current_user] = previous_user_override


@pytest.fixture(autouse=True)
def reset_enforcer_state(monkeypatch):
    db = TestSession()
    try:
        db.query(Policy).delete()
        db.commit()
    finally:
        db.close()

    enforcer.blocked_domains.clear()
    enforcer.blocked_ips.clear()
    enforcer.ml_policies.clear()
    enforcer.isolated_endpoints.clear()
    enforcer.policy_state.clear()
    enforcer._deferred_policies.clear()
    monkeypatch.setattr(enforcer, "_rewrite_hosts_file", lambda: True)
    monkeypatch.setattr(enforcer, "_delete_firewall_rule", lambda rule_name: True)
    monkeypatch.setattr(enforcer, "_block_domains", lambda policy_id, domains: True)
    monkeypatch.setattr(enforcer, "_block_ips", lambda policy_id, ips: True)
    monkeypatch.setattr(enforcer, "_unblock_domains_list", lambda domains: True)
    monkeypatch.setattr(enforcer, "_unblock_ips_list", lambda ips: True)
    monkeypatch.setattr(enforcer, "_resolve_domain_ips", lambda domains: [])
    yield
    enforcer.blocked_domains.clear()
    enforcer.blocked_ips.clear()
    enforcer.ml_policies.clear()
    enforcer.isolated_endpoints.clear()
    enforcer.policy_state.clear()
    enforcer._deferred_policies.clear()


def _auth_headers() -> dict:
    return {"Authorization": "Bearer test-token"}


class TestNLPPolicyParser:
    def test_parser_examples(self):
        parser = NLPPolicyParser()

        parsed = parser.parse("block youtube")
        assert parsed.purpose == "block"
        assert "youtube.com" in parsed.domains
        assert "googlevideo.com" in parsed.domains

        parsed = parser.parse("block youtube.com")
        assert parsed.purpose == "block"
        assert "youtube.com" in parsed.domains

        parsed = parser.parse("block youtube between 9pm and 6am")
        assert parsed.time_range == {"start": "21:00", "end": "06:00"}

        parsed = parser.parse("block instagram for 2 hours")
        assert parsed.auto_expire == 7200
        assert "instagram.com" in parsed.domains

        parsed = parser.parse("allow google always")
        assert parsed.purpose == "unblock"
        assert "google.com" in parsed.domains
        assert parsed.time_range is None
        assert parsed.auto_expire is None

        parsed = parser.parse("block facebook for 30 minutes")
        assert parsed.auto_expire == 1800
        assert "facebook.com" in parsed.domains

    def test_until_time_is_parsed(self):
        parser = NLPPolicyParser()
        parsed = parser.parse("block youtube until 6pm")
        assert parsed.time_range == {"start": "00:00", "end": "18:00"}


class TestPolicyDatabaseStorage:
    def test_natural_language_policy_persists_duration(self):
        response = client.post(
            "/api/policies",
            json={
                "name": "Instagram Cooldown",
                "natural_language": "block instagram for 2 hours",
                "is_active": True,
            },
            headers=_auth_headers(),
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["purpose"] == "block"
        assert payload["conditions"]["auto_expire"] == 7200
        assert "instagram.com" in payload["conditions"]["domains"]

        db = TestSession()
        try:
            policy = db.query(Policy).filter(Policy.id == payload["id"]).first()
            assert policy is not None
            assert policy.conditions["auto_expire"] == 7200
            assert "instagram.com" in policy.conditions["domains"]
            assert policy.is_active is True
        finally:
            db.close()


class TestPolicyScheduler:
    def test_scheduler_activates_time_window_policy(self, monkeypatch):
        db = TestSession()
        try:
            policy = Policy(
                name="Night YouTube",
                purpose="block",
                conditions={"domains": ["youtube.com"], "time_range": {"start": "21:00", "end": "06:00"}},
                is_active=True,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)

            calls = []
            monkeypatch.setattr(
                "app.services.enforcer._is_within_time_range",
                lambda conditions: True,
            )

            def fake_enforce(policy_id, purpose, conditions, _skip_time_check=False):
                calls.append((policy_id, purpose, conditions, _skip_time_check))
                enforcer.blocked_domains[policy_id] = conditions.get("domains", [])
                return {"status": "enforced", "enforced": True}

            monkeypatch.setattr(enforcer, "enforce_policy", fake_enforce)

            enforcer.check_time_policies_from_db(db)
            assert calls
            assert calls[0][0] == policy.id
            assert policy.id in enforcer.blocked_domains
        finally:
            db.close()

    def test_scheduler_unenforces_expired_time_window_policy(self, monkeypatch):
        db = TestSession()
        try:
            policy = Policy(
                name="Office YouTube",
                purpose="block",
                conditions={"domains": ["youtube.com"], "time_range": {"start": "09:00", "end": "17:00"}},
                is_active=True,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)

            enforcer.blocked_domains[policy.id] = ["youtube.com"]
            enforcer.policy_state[policy.id] = {"purpose": "block", "conditions": policy.conditions}

            calls = []
            monkeypatch.setattr(
                "app.services.enforcer._is_within_time_range",
                lambda conditions: False,
            )

            def fake_unenforce(policy_id):
                calls.append(policy_id)
                enforcer.blocked_domains.pop(policy_id, None)
                return {"status": "unenforced"}

            monkeypatch.setattr(enforcer, "unenforce_policy", fake_unenforce)

            enforcer.check_time_policies_from_db(db)
            assert calls == [policy.id]
            assert policy.id in enforcer._deferred_policies
        finally:
            db.close()

    def test_scheduler_disables_auto_expired_policy(self):
        db = TestSession()
        try:
            policy = Policy(
                name="Temporary Facebook Block",
                purpose="block",
                conditions={"domains": ["facebook.com"], "auto_expire": 60},
                is_active=True,
                created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)

            enforcer.blocked_domains[policy.id] = ["facebook.com"]
            enforcer.policy_state[policy.id] = {"purpose": "block", "conditions": policy.conditions}

            enforcer.check_time_policies_from_db(db)
            db.refresh(policy)

            assert policy.is_active is False
            assert policy.id not in enforcer.blocked_domains
            assert policy.id not in enforcer.policy_state
        finally:
            db.close()
