import uuid
import random
import socket
from datetime import datetime, timezone, timedelta

import bcrypt
from sqlalchemy.orm import Session


def _get_local_ip() -> str:
    """Detect this machine's LAN IP automatically."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

from app.models.user import User
from app.models.endpoint import Endpoint
from app.models.application import Application
from app.models.policy import Policy
from app.models.alert import Alert
from app.models.network_usage import NetworkUsage
from app.models.ml_prediction import MLPrediction


def seed_database(db: Session) -> None:
    """Seed the database with real configuration. Only runs if the DB is empty."""

    if db.query(User).first() is not None:
        return

    now = datetime.now(timezone.utc)

    # --- Admin user ---
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@guardian.com",
        hashed_password=bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode("utf-8"),
        name="Admin User",
        role="admin",
        created_at=now - timedelta(days=30),
    )
    db.add(admin)

    # --- Real endpoint: this machine (IP detected automatically) ---
    local_ip = _get_local_ip()
    dev_machine = Endpoint(
        id=str(uuid.uuid4()),
        name="Dev Machine",
        ip_address=local_ip,
        status="active",
        created_at=now,
    )
    db.add(dev_machine)

    # --- Applications running on this machine ---
    apps_data = [
        ("Python Backend", "python.exe"),
        ("Node Frontend", "node.exe"),
        ("Browser", "chrome.exe"),
    ]
    for app_name, proc_name in apps_data:
        app = Application(
            id=str(uuid.uuid4()),
            name=app_name,
            process_name=proc_name,
            status="running",
            endpoint_id=dev_machine.id,
            created_at=now,
        )
        db.add(app)

    # --- Starter policies (real, useful rules) ---
    policy_templates = [
        (
            "Block External SSH",
            "Block all SSH traffic from external sources",
            "block",
            {"domains": [], "ips": [], "ports": [{"port": 22, "protocol": ["TCP"]}],
             "app_names": [], "anomaly_threshold": None, "rate_limit": None},
        ),
        (
            "Rate Limit API",
            "Limit API requests to 1000/min per IP",
            "block",
            {"domains": [], "ips": [], "ports": [{"port": 8080, "protocol": ["TCP"]}],
             "app_names": ["node"], "rate_limit": 1000, "anomaly_threshold": None},
        ),
        (
            "Allow HTTPS Only",
            "Only allow encrypted HTTPS traffic on port 80",
            "block",
            {"domains": [], "ips": [], "ports": [{"port": 80, "protocol": ["TCP"]}],
             "app_names": [], "anomaly_threshold": None, "rate_limit": None},
        ),
        (
            "Block SQL Injection",
            "Block requests containing SQL injection patterns on DB ports",
            "block",
            {"domains": [], "ips": [],
             "ports": [{"port": 3306, "protocol": ["TCP"]}, {"port": 5432, "protocol": ["TCP"]}],
             "app_names": [], "attack_types": ["SQL Injection"],
             "anomaly_threshold": None, "rate_limit": None},
        ),
        (
            "Bandwidth Throttle",
            "Throttle bandwidth during peak hours 9am-5pm",
            "block",
            {"domains": [], "ips": [], "ports": [], "app_names": [],
             "time_range": {"start": "09:00", "end": "17:00"},
             "rate_limit": 500000, "anomaly_threshold": None},
        ),
        (
            "Block Tor Exit Nodes",
            "Block traffic from known Tor exit node ranges",
            "block",
            {"domains": [], "ips": ["185.220.101.0/24", "23.129.64.0/24"],
             "ports": [], "app_names": [], "geo_countries": ["XX"],
             "anomaly_threshold": None, "rate_limit": None},
        ),
        (
            "High Anomaly Block",
            "Auto-block any flow with ML anomaly score above 0.85",
            "block",
            {"domains": [], "ips": [], "ports": [], "app_names": [],
             "anomaly_threshold": 0.85, "rate_limit": None},
        ),
        (
            "Log DNS Queries",
            "Log all DNS queries for analysis",
            "block",
            {"domains": [], "ips": [],
             "ports": [{"port": 53, "protocol": ["UDP", "TCP"]}],
             "app_names": [], "anomaly_threshold": None, "rate_limit": None},
        ),
    ]

    for name, desc, purpose, conditions in policy_templates:
        policy = Policy(
            id=str(uuid.uuid4()),
            name=name,
            description=desc,
            purpose=purpose,
            conditions=conditions,
            endpoint_id=dev_machine.id,
            is_active=False,  # all policies start inactive — enable from UI
            created_at=now,
        )
        db.add(policy)

    db.commit()
    print(f"Database seeded: Dev Machine ({local_ip}) + 8 starter policies. Alerts and predictions will be generated by the ML engine.")
