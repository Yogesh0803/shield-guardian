import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.models.alert import Alert
from app.models.alert_feedback import AlertFeedback
from app.models.alert_silence_rule import AlertSilenceRule
from app.models.endpoint import Endpoint
from app.models.application import Application
from app.models.policy import Policy
from app.schemas.alert import (
    AlertResponse,
    FalsePositiveAction,
    SilenceRuleAction,
    WhitelistAction,
)
from app.middleware.auth import get_current_user
from app.models.user import User
from app.services.enforcer import enforcer
from app.services.feedback_loop import get_tuning_summary, record_feedback

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _first_ipv4(text: str) -> Optional[str]:
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None


def _feedback_map_for_alert_ids(db: Session, alert_ids: List[str]) -> dict:
    if not alert_ids:
        return {}
    rows = (
        db.query(AlertFeedback)
        .filter(AlertFeedback.alert_id.in_(alert_ids))
        .order_by(AlertFeedback.created_at.desc())
        .all()
    )
    by_alert = {}
    for row in rows:
        if row.alert_id not in by_alert:
            by_alert[row.alert_id] = row
    return by_alert


def _alert_to_dict(row, latest_feedback: Optional[AlertFeedback] = None):
    """Convert a (Alert, endpoint_name, app_name) row tuple to dict."""
    a, endpoint_name, app_name = row
    whitelisted_target = None
    silenced_rule_id = None
    feedback_note = None
    feedback_action = None
    is_false_positive = False

    if latest_feedback:
        feedback_action = latest_feedback.action_type
        is_false_positive = latest_feedback.action_type == "false_positive"
        feedback_note = latest_feedback.note
        if latest_feedback.target_type and latest_feedback.target_value:
            whitelisted_target = f"{latest_feedback.target_type}:{latest_feedback.target_value}"
        silenced_rule_id = latest_feedback.silence_rule_id

    return {
        "id": a.id,
        "severity": a.severity,
        "category": a.category,
        "attack_type": a.attack_type,
        "message": a.message,
        "confidence": a.confidence,
        "app_id": a.app_id,
        "app_name": app_name,
        "endpoint_id": a.endpoint_id,
        "endpoint_name": endpoint_name,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "feedback_action": feedback_action,
        "is_false_positive": is_false_positive,
        "whitelisted_target": whitelisted_target,
        "silenced_rule_id": silenced_rule_id,
        "feedback_note": feedback_note,
    }


def _record_feedback(
    db: Session,
    alert: Alert,
    user: User,
    action_type: str,
    note: Optional[str] = None,
    target_type: Optional[str] = None,
    target_value: Optional[str] = None,
    policy_id: Optional[str] = None,
    silence_rule_id: Optional[str] = None,
):
    feedback = AlertFeedback(
        id=str(uuid.uuid4()),
        alert_id=alert.id,
        action_type=action_type,
        target_type=target_type,
        target_value=target_value,
        policy_id=policy_id,
        silence_rule_id=silence_rule_id,
        note=note,
        created_by=user.id,
    )
    db.add(feedback)

    record_feedback(
        {
            "alert_id": alert.id,
            "action_type": action_type,
            "target_type": target_type,
            "target_value": target_value,
            "policy_id": policy_id,
            "silence_rule_id": silence_rule_id,
            "note": note,
            "alert": {
                "severity": alert.severity,
                "category": alert.category,
                "attack_type": alert.attack_type,
                "confidence": alert.confidence,
                "endpoint_id": alert.endpoint_id,
                "message": alert.message,
            },
            "reviewed_by": user.email,
        }
    )
    return feedback


@router.get("/feedback/tuning-summary")
def feedback_tuning_summary(current_user: User = Depends(get_current_user)):
    return get_tuning_summary()


@router.get("")
def list_alerts(
    endpoint_id: Optional[str] = Query(None),
    app_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        db.query(Alert, Endpoint.name, Application.name)
        .outerjoin(Endpoint, Alert.endpoint_id == Endpoint.id)
        .outerjoin(Application, Alert.app_id == Application.id)
    )

    if endpoint_id:
        query = query.filter(Alert.endpoint_id == endpoint_id)
    if app_id:
        query = query.filter(Alert.app_id == app_id)
    if severity:
        query = query.filter(Alert.severity == severity)

    rows = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    feedback_map = _feedback_map_for_alert_ids(db, [a.id for a, _, _ in rows])
    return [_alert_to_dict(row, feedback_map.get(row[0].id)) for row in rows]


@router.get("/endpoint/{endpoint_id}/app/{app_id}")
def get_alerts_for_endpoint_app(
    endpoint_id: str,
    app_id: str,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.query(Alert, Endpoint.name, Application.name)
        .outerjoin(Endpoint, Alert.endpoint_id == Endpoint.id)
        .outerjoin(Application, Alert.app_id == Application.id)
        .filter(Alert.endpoint_id == endpoint_id, Alert.app_id == app_id)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )
    feedback_map = _feedback_map_for_alert_ids(db, [a.id for a, _, _ in rows])
    return [_alert_to_dict(row, feedback_map.get(row[0].id)) for row in rows]


@router.post("/{alert_id}/false-positive")
def mark_false_positive(
    alert_id: str,
    payload: FalsePositiveAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    feedback = _record_feedback(
        db,
        alert,
        current_user,
        action_type="false_positive",
        note=payload.note,
    )
    db.commit()
    return {
        "status": "ok",
        "alert_id": alert.id,
        "feedback_id": feedback.id,
        "action": "false_positive",
    }


@router.post("/{alert_id}/whitelist")
def whitelist_from_alert(
    alert_id: str,
    payload: WhitelistAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    target_value = (payload.target_value or "").strip()
    if not target_value:
        if payload.target_type == "ip":
            target_value = _first_ipv4(alert.message or "") or ""
        elif payload.target_type == "app" and alert.app_id:
            app = db.query(Application).filter(Application.id == alert.app_id).first()
            target_value = app.name if app else ""

    if not target_value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target_value is required for this whitelist action",
        )

    conditions = {}
    if payload.target_type == "ip":
        conditions["ips"] = [target_value]
    elif payload.target_type == "domain":
        conditions["domains"] = [target_value]
    else:
        conditions["app_names"] = [target_value]

    policy = Policy(
        name=f"Whitelist {payload.target_type}: {target_value}",
        description=f"Auto-created from alert {alert.id} by {current_user.email}",
        purpose="unblock",
        conditions=conditions,
        endpoint_id=alert.endpoint_id,
        is_active=True,
    )
    db.add(policy)
    db.flush()

    try:
        enforcer.enforce_policy(policy.id, policy.purpose, policy.conditions or {})
    except Exception:
        # Whitelist policy is still persisted even if live unenforcement fails.
        pass

    feedback = _record_feedback(
        db,
        alert,
        current_user,
        action_type="whitelist",
        note=payload.note,
        target_type=payload.target_type,
        target_value=target_value,
        policy_id=policy.id,
    )

    db.commit()
    return {
        "status": "ok",
        "alert_id": alert.id,
        "feedback_id": feedback.id,
        "policy_id": policy.id,
        "target_type": payload.target_type,
        "target_value": target_value,
    }


@router.post("/{alert_id}/silence-rule")
def silence_from_alert(
    alert_id: str,
    payload: SilenceRuleAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    silenced_policy_id = None
    if payload.policy_id:
        policy = db.query(Policy).filter(Policy.id == payload.policy_id).first()
        if not policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
        policy.is_active = False
        silenced_policy_id = policy.id
        try:
            enforcer.unenforce_policy(policy.id)
        except Exception:
            pass

    app_name = None
    if alert.app_id:
        app = db.query(Application).filter(Application.id == alert.app_id).first()
        app_name = app.name if app else None

    rule = AlertSilenceRule(
        id=str(uuid.uuid4()),
        name=f"Silence {alert.attack_type or alert.category} @ {alert.endpoint_id}",
        endpoint_id=alert.endpoint_id,
        attack_type=alert.attack_type,
        app_name=app_name,
        src_ip=None,
        dst_ip=None,
        is_active=True,
    )
    db.add(rule)
    db.flush()

    feedback = _record_feedback(
        db,
        alert,
        current_user,
        action_type="silence_rule",
        note=payload.note,
        policy_id=silenced_policy_id,
        silence_rule_id=rule.id,
    )

    db.commit()
    return {
        "status": "ok",
        "alert_id": alert.id,
        "feedback_id": feedback.id,
        "silence_rule_id": rule.id,
        "policy_id": silenced_policy_id,
    }
