"""
Manual time-based blocking verification script.

This is intentionally not an automated pytest module. Run it directly
against a live backend when you want to validate scheduled enforcement.
"""

import subprocess
import sys
import time
from datetime import datetime, timedelta

import requests

BASE = "http://localhost:8000"
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def check_youtube_hosts():
    try:
        with open(HOSTS, "r", encoding="utf-8") as handle:
            return sum(
                1
                for line in handle
                if "youtube" in line.lower() and line.strip().startswith("127.0.0.1")
            )
    except OSError:
        return -1


def check_youtube_http():
    try:
        requests.get("https://youtube.com", timeout=4)
        return False
    except requests.RequestException:
        return True


def main():
    log("Logging in...")
    response = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": "admin@guardian.com", "password": "password123"},
        timeout=10,
    )
    if response.status_code != 200:
        log(f"FATAL: Login failed: {response.text}")
        return 1

    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    log("Login OK")

    status = requests.get(f"{BASE}/api/policies/status", headers=headers, timeout=10).json()
    log(f"Backend is_admin: {status.get('is_admin')}")

    now = datetime.now()
    start_time = (now + timedelta(minutes=1)).strftime("%H:%M")
    end_time = (now + timedelta(minutes=3)).strftime("%H:%M")

    log(f"Creating policy: block youtube {start_time} to {end_time}")
    response = requests.post(
        f"{BASE}/api/policies",
        json={
            "name": f"TimeBlock YouTube {start_time}-{end_time}",
            "description": "Automated time-based blocking test",
            "purpose": "block",
            "conditions": {
                "domains": ["youtube.com"],
                "time_range": {"start": start_time, "end": end_time},
            },
            "is_active": True,
        },
        headers=headers,
        timeout=10,
    )
    if response.status_code != 200:
        log(f"FATAL: Policy creation failed: {response.status_code} {response.text}")
        return 1

    policy = response.json()
    policy_id = policy["id"]
    log(f"Policy created: {policy_id}")
    log(f"  conditions: {policy.get('conditions')}")

    status = requests.get(f"{BASE}/api/policies/status", headers=headers, timeout=10).json()
    deferred = policy_id in status.get("deferred_policies", {})
    enforced = policy_id in status.get("blocked_domain_policies", {})
    log(f"Initial: deferred={deferred}, enforced={enforced}")

    log("=" * 60)
    log("Polling every 5s (max 5 min)...")
    activated = False
    deactivated = False
    activated_at = None
    deactivated_at = None

    for i in range(60):
        time.sleep(5)
        now_str = datetime.now().strftime("%H:%M:%S")
        try:
            status = requests.get(f"{BASE}/api/policies/status", headers=headers, timeout=10).json()
        except requests.RequestException as exc:
            log(f"[{i + 1:2d}] ERROR: {exc}")
            continue

        is_enforced = policy_id in status.get("blocked_domain_policies", {})
        is_deferred = policy_id in status.get("deferred_policies", {})
        hosts_n = check_youtube_hosts()
        state = "ENFORCED" if is_enforced else ("DEFERRED" if is_deferred else "NEITHER")
        print(f"  [{i + 1:2d}] {now_str} | {state:10s} | hosts_entries={hosts_n}", flush=True)

        if is_enforced and not activated:
            activated = True
            activated_at = now_str
            http_blocked = check_youtube_http()
            log(f"  >>> ACTIVATED! hosts={hosts_n}, http_blocked={http_blocked}")

        if activated and not is_enforced and not deactivated:
            deactivated = True
            deactivated_at = now_str
            hosts_n2 = check_youtube_hosts()
            http_blocked2 = check_youtube_http()
            log(f"  >>> DEACTIVATED! hosts={hosts_n2}, http_blocked={http_blocked2}")
            break

    log("=" * 60)
    try:
        requests.delete(f"{BASE}/api/policies/{policy_id}", headers=headers, timeout=10)
        log("Test policy deleted")
    except requests.RequestException:
        pass

    log("=" * 60)
    if activated and deactivated:
        log(f"RESULT: SUCCESS - Activated at {activated_at}, deactivated at {deactivated_at}")
        log(f"   Time window was: {start_time} to {end_time}")
        return 0
    if activated:
        log(f"RESULT: PARTIAL - Activated at {activated_at}, test ended before deactivation")
        return 0

    log(f"RESULT: FAILED - Never activated during {start_time} to {end_time}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
