from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.models.alert import Alert
from app.models.endpoint import Endpoint
from app.models.application import Application
from app.schemas.alert import AlertResponse
from app.middleware.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _alert_to_dict(row):
    """Convert a (Alert, endpoint_name, app_name) row tuple to dict."""
    a, endpoint_name, app_name = row
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
    }


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
    return [_alert_to_dict(row) for row in rows]


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
    return [_alert_to_dict(row) for row in rows]
