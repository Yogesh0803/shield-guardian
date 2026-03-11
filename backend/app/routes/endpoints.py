import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
from typing import List

from app.database import get_db
from app.models.endpoint import Endpoint
from app.models.application import Application
from app.models.network_usage import NetworkUsage
from app.schemas.endpoint import (
    EndpointCreate,
    EndpointResponse,
    EndpointListResponse,
    AlertBrief,
    AppCreate,
    AppResponse,
)
from app.middleware.auth import get_current_user
from app.models.user import User

logger = logging.getLogger("guardian_shield.endpoints")

router = APIRouter(prefix="/api/endpoints", tags=["Endpoints"])


def _build_list_response(ep: Endpoint, traffic_count: int) -> EndpointListResponse:
    """Build EndpointListResponse with computed traffic_logs."""
    data = EndpointListResponse.model_validate(ep)
    data.traffic_logs = traffic_count
    return data


def _build_detail_response(ep: Endpoint) -> EndpointResponse:
    """Build EndpointResponse with recent_alerts and traffic_logs."""
    # Build alert briefs with app_name resolved from the application relationship
    alert_briefs = []
    for alert in (ep.alerts or []):
        brief = AlertBrief.model_validate(alert)
        if alert.application:
            brief.app_name = alert.application.name
        alert_briefs.append(brief)

    data = EndpointResponse.model_validate(ep)
    data.recent_alerts = alert_briefs
    data.traffic_logs = len(ep.network_usages) if ep.network_usages else 0
    return data


@router.get("", response_model=List[EndpointListResponse])
def list_endpoints(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    logger.info("Listing all endpoints for user=%s", current_user.email)
    endpoints = db.query(Endpoint).all()

    # Efficiently count network_usages per endpoint in one query
    traffic_counts_raw = (
        db.query(NetworkUsage.endpoint_id, func.count(NetworkUsage.id))
        .group_by(NetworkUsage.endpoint_id)
        .all()
    )
    traffic_map = {eid: cnt for eid, cnt in traffic_counts_raw}

    logger.debug("Found %d endpoints", len(endpoints))
    return [_build_list_response(ep, traffic_map.get(ep.id, 0)) for ep in endpoints]


@router.get("/{endpoint_id}", response_model=EndpointResponse)
def get_endpoint(
    endpoint_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    logger.info("Fetching endpoint id=%s for user=%s", endpoint_id, current_user.email)
    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        logger.warning("Endpoint id=%s not found", endpoint_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found",
        )
    return _build_detail_response(endpoint)


@router.post("/{endpoint_id}/apps", response_model=AppResponse)
def add_app_to_endpoint(
    endpoint_id: str,
    app_data: AppCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    logger.info(
        "Adding app '%s' to endpoint id=%s by user=%s",
        app_data.name, endpoint_id, current_user.email,
    )
    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        logger.warning("Endpoint id=%s not found for add_app", endpoint_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found",
        )

    application = Application(
        name=app_data.name,
        process_name=app_data.process_name,
        status=app_data.status,
        endpoint_id=endpoint_id,
    )
    db.add(application)
    db.commit()
    db.refresh(application)

    logger.info("App '%s' (id=%s) added to endpoint id=%s", app_data.name, application.id, endpoint_id)
    return AppResponse.model_validate(application)
