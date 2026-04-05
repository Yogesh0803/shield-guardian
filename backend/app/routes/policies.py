import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.policy import Policy
from app.models.ml_prediction import MLPrediction
from app.models.endpoint import Endpoint
from app.models.user import User
from app.schemas.policy import (
    NLPPolicyParse,
    NLPPolicyParseResponse,
    PolicyCreate,
    PolicySimulationRequest,
    PolicySimulationResponse,
    PolicyResponse,
)
from app.services.enforcer import enforcer
from ml.enforcer.nlp_parser import NLPPolicyParser, ParsedPolicy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/policies", tags=["Policies"])
_parser = NLPPolicyParser()


def _safe_list(value) -> list:
    return value if isinstance(value, list) else []


def _safe_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _flow_matches_conditions(
    purpose: str,
    conditions: Dict[str, object],
    row: MLPrediction,
    endpoint_ip: Optional[str],
) -> bool:
    checks: List[bool] = []
    conditions = _safe_dict(conditions)
    context = _safe_dict(row.context_json)

    src_ip = row.src_ip or ""
    dst_ip = row.dst_ip or ""
    app_name = (row.app_name or context.get("app_name") or "").lower()
    protocol = (row.protocol or "").upper()
    dst_port = row.dst_port
    anomaly_score = float(row.anomaly_score or 0.0)
    confidence = float(row.confidence or 0.0)
    attack_type = row.attack_type or "Unknown"

    # endpoint scoping from endpoint_id in the policy
    if endpoint_ip:
        checks.append(src_ip == endpoint_ip or dst_ip == endpoint_ip)

    ips = _safe_list(conditions.get("ips"))
    if ips:
        checks.append(src_ip in ips or dst_ip in ips)

    app_names = [str(a).lower() for a in _safe_list(conditions.get("app_names"))]
    if app_names:
        checks.append(app_name in app_names)

    protocols = [str(p).upper() for p in _safe_list(conditions.get("protocols"))]
    if protocols:
        checks.append(protocol in protocols)

    ports = _safe_list(conditions.get("ports"))
    if ports:
        port_match = False
        for p in ports:
            if not isinstance(p, dict):
                continue
            if dst_port != p.get("port"):
                continue
            allowed_protocols = [str(x).upper() for x in _safe_list(p.get("protocol"))]
            if not allowed_protocols or protocol in allowed_protocols:
                port_match = True
                break
        checks.append(port_match)

    anomaly_threshold = conditions.get("anomaly_threshold")
    if anomaly_threshold is not None:
        checks.append(anomaly_score >= float(anomaly_threshold))

    confidence_threshold = conditions.get("confidence_threshold")
    if confidence_threshold is not None:
        checks.append(confidence >= float(confidence_threshold))

    attack_types = [str(a) for a in _safe_list(conditions.get("attack_types"))]
    if attack_types:
        checks.append(attack_type in attack_types)

    geo_countries = [str(c).upper() for c in _safe_list(conditions.get("geo_countries"))]
    if geo_countries:
        code = str(context.get("dest_country_code") or context.get("dest_country") or "").upper()
        checks.append(code in geo_countries)

    # Time-window checks (local hour/day inferred from prediction timestamp)
    schedule = _safe_dict(conditions.get("schedule"))
    time_range = _safe_dict(schedule.get("time_range") or conditions.get("time_range"))
    days_of_week = schedule.get("days") if schedule.get("days") is not None else conditions.get("days_of_week")

    ts = row.timestamp
    if ts is not None:
        ts_local = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        now_local = ts_local.astimezone()
        minute = now_local.hour * 60 + now_local.minute
        if time_range and time_range.get("start") and time_range.get("end"):
            sh, sm = [int(x) for x in str(time_range["start"]).split(":")]
            eh, em = [int(x) for x in str(time_range["end"]).split(":")]
            start_m = sh * 60 + sm
            end_m = eh * 60 + em
            if start_m <= end_m:
                checks.append(start_m <= minute < end_m)
            else:
                checks.append(minute >= start_m or minute < end_m)
        if isinstance(days_of_week, list) and days_of_week:
            checks.append(now_local.weekday() in days_of_week)

    if not checks:
        return False

    # For non-block purposes, condition match still means this policy would have affected flow.
    # The caller decides wording via purpose.
    return all(checks)


def _estimate_risk(rows: List[MLPrediction], affected: List[MLPrediction], purpose: str) -> Dict[str, object]:
    total = max(len(rows), 1)
    if not affected:
        return {
            "score": 0,
            "level": "low",
            "reason": "No affected historical flows",
        }

    avg_anomaly = sum(float(r.anomaly_score or 0.0) for r in affected) / len(affected)
    avg_conf = sum(float(r.confidence or 0.0) for r in affected) / len(affected)
    attack_like = sum(1 for r in affected if (r.attack_type or "").lower() not in ("benign", "unknown"))
    affected_ratio = len(affected) / total

    purpose_multiplier = {
        "block": 1.0,
        "isolate": 0.95,
        "rate_limit": 0.8,
        "alert": 0.5,
        "monitor": 0.4,
        "unblock": 0.7,
    }.get(purpose, 0.7)

    raw = (
        (affected_ratio * 45)
        + (avg_anomaly * 25)
        + (avg_conf * 15)
        + ((attack_like / max(len(affected), 1)) * 15)
    ) * purpose_multiplier
    score = int(max(0, min(100, round(raw))))

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "avg_anomaly_score": round(avg_anomaly, 3),
        "avg_confidence": round(avg_conf, 3),
        "affected_ratio": round(affected_ratio, 4),
    }


def _rule_type_for(parsed: ParsedPolicy) -> str:
    if parsed.isolation_scope:
        return "isolation"
    if parsed.rate_limit is not None:
        return "rate_limit"
    if parsed.attack_types:
        return "attack"
    if parsed.anomaly_threshold is not None or parsed.confidence_threshold is not None:
        return "anomaly"
    if parsed.monitor_mode or parsed.monitor_duration:
        return "monitor"
    if parsed.time_range or parsed.schedule:
        return "time_access"
    return "basic"


def _capabilities_for(parsed: ParsedPolicy) -> List[str]:
    capabilities: List[str] = []
    if parsed.rate_limit is not None:
        capabilities.append("rate_limiting")
    if parsed.isolation_scope:
        capabilities.append("endpoint_isolation")
    if parsed.monitor_mode or parsed.monitor_duration or parsed.purpose == "monitor":
        capabilities.append("monitoring")
    if parsed.purpose == "alert":
        capabilities.append("alerting")
    if parsed.attack_types:
        capabilities.append("attack_classification")
    if parsed.anomaly_threshold is not None or parsed.confidence_threshold is not None:
        capabilities.append("anomaly_score")
    if parsed.time_range or parsed.schedule:
        capabilities.append("time_based_access")
    return capabilities


def _parsed_to_conditions(parsed: ParsedPolicy) -> Dict[str, object]:
    conditions: Dict[str, object] = {
        "domains": parsed.domains,
        "ips": parsed.ips,
        "ports": parsed.ports,
        "app_names": parsed.app_names,
    }
    if parsed.time_range:
        conditions["time_range"] = parsed.time_range
    if parsed.days_of_week is not None:
        conditions["days_of_week"] = parsed.days_of_week
    if parsed.geo_countries:
        conditions["geo_countries"] = parsed.geo_countries
    if parsed.anomaly_threshold is not None:
        conditions["anomaly_threshold"] = parsed.anomaly_threshold
    if parsed.attack_types:
        conditions["attack_types"] = parsed.attack_types
    if parsed.rate_limit is not None:
        conditions["rate_limit"] = parsed.rate_limit
        conditions["rate_limit_window"] = parsed.rate_limit_window or 60
        conditions["rate_limit_action"] = parsed.rate_limit_action or "block"
    if parsed.confidence_threshold is not None:
        conditions["confidence_threshold"] = parsed.confidence_threshold
    if parsed.severity:
        conditions["severity"] = parsed.severity
    if parsed.isolation_scope:
        conditions["isolation_scope"] = parsed.isolation_scope
        conditions["isolation_targets"] = parsed.isolation_targets
    if parsed.monitor_mode:
        conditions["monitor_mode"] = parsed.monitor_mode
    if parsed.monitor_duration:
        conditions["monitor_duration"] = parsed.monitor_duration
    if parsed.protocols:
        conditions["protocols"] = parsed.protocols
    if parsed.schedule:
        conditions["schedule"] = parsed.schedule
    if parsed.auto_expire:
        conditions["auto_expire"] = parsed.auto_expire
    return conditions


def _merge_conditions(
    parsed_conditions: Dict[str, object],
    provided_conditions: Optional[Dict[str, object]],
) -> Dict[str, object]:
    if not provided_conditions:
        return parsed_conditions

    merged = dict(parsed_conditions)
    for key, value in provided_conditions.items():
        if value is None:
            continue
        if isinstance(value, list):
            merged[key] = value
        elif isinstance(value, dict):
            nested = dict(merged.get(key, {})) if isinstance(merged.get(key), dict) else {}
            nested.update(value)
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def _build_policy_from_request(policy_data: PolicyCreate) -> Policy:
    text = (policy_data.natural_language or "").strip()
    parsed: Optional[ParsedPolicy] = None
    if text:
        parsed = _parser.parse(text)
        logger.info(
            "[PolicyEngine] NLP parsed policy: purpose=%s domains=%s ips=%s time_range=%s auto_expire=%s",
            parsed.purpose,
            parsed.domains,
            parsed.ips,
            parsed.time_range,
            parsed.auto_expire,
        )

    purpose = policy_data.purpose or (parsed.purpose if parsed else None)
    conditions = _merge_conditions(
        _parsed_to_conditions(parsed) if parsed else {},
        policy_data.conditions,
    )

    if not purpose:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Policy purpose is required",
        )

    if not conditions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Policy conditions are required",
        )

    name = policy_data.name.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Policy name is required",
        )

    description = policy_data.description.strip() if policy_data.description else text or None

    return Policy(
        name=name,
        description=description,
        purpose=purpose,
        conditions=conditions,
        endpoint_id=policy_data.endpoint_id,
        is_active=policy_data.is_active,
    )


@router.get("", response_model=List[PolicyResponse])
def list_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policies = db.query(Policy).all()
    return [PolicyResponse.model_validate(policy) for policy in policies]


@router.get("/status")
def enforcer_status(current_user: User = Depends(get_current_user)):
    return enforcer.get_status()


@router.get("/endpoint/{endpoint_id}", response_model=List[PolicyResponse])
def get_policies_by_endpoint(
    endpoint_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policies = db.query(Policy).filter(Policy.endpoint_id == endpoint_id).all()
    return [PolicyResponse.model_validate(policy) for policy in policies]


@router.post("", response_model=PolicyResponse)
def create_policy(
    policy_data: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = _build_policy_from_request(policy_data)

    logger.info(
        "Creating policy: name=%r purpose=%r conditions=%s",
        policy.name,
        policy.purpose,
        policy.conditions,
    )

    db.add(policy)
    db.commit()
    db.refresh(policy)

    if policy.is_active and policy.conditions and policy.purpose:
        try:
            result = enforcer.enforce_policy(policy.id, policy.purpose, policy.conditions)
            logger.info("Policy %r enforcement result: %s", policy.name, result)
        except Exception as exc:
            logger.error("Enforcement failed for %r: %s", policy.name, exc)

    return PolicyResponse.model_validate(policy)


@router.post("/simulate", response_model=PolicySimulationResponse)
def simulate_policy(
    payload: PolicySimulationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = _build_policy_from_request(payload.policy)
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=payload.hours)

    query = (
        db.query(MLPrediction)
        .filter(MLPrediction.timestamp >= cutoff)
        .order_by(MLPrediction.timestamp.desc())
        .limit(payload.max_samples)
    )
    rows: List[MLPrediction] = query.all()

    # Fallback to latest available historical (seeded/demo) data when
    # no recent flows exist inside the requested window.
    if not rows:
        rows = (
            db.query(MLPrediction)
            .order_by(MLPrediction.timestamp.desc())
            .limit(min(payload.max_samples, 2000))
            .all()
        )

    endpoint_ip: Optional[str] = None
    if policy.endpoint_id:
        ep = db.query(Endpoint.ip_address).filter(Endpoint.id == policy.endpoint_id).first()
        endpoint_ip = ep[0] if ep else None

    affected = [
        row
        for row in rows
        if _flow_matches_conditions(policy.purpose or "block", policy.conditions or {}, row, endpoint_ip)
    ]

    # Domains are best-effort from context; fallback to destination IP.
    app_counts = Counter((row.app_name or "unknown") for row in affected)
    domain_counts = Counter(
        str(_safe_dict(row.context_json).get("dest_domain") or row.dst_ip or "unknown")
        for row in affected
    )

    top_apps = [{"name": k, "count": v} for k, v in app_counts.most_common(5)]
    top_domains = [{"name": k, "count": v} for k, v in domain_counts.most_common(5)]

    total = len(rows)
    affected_count = len(affected)
    would_block_percent = round((affected_count / total) * 100, 2) if total else 0.0

    return PolicySimulationResponse(
        total_flows=total,
        affected_flows=affected_count,
        would_block_percent=would_block_percent,
        top_affected_apps=top_apps,
        top_affected_domains=top_domains,
        estimated_risk=_estimate_risk(rows, affected, policy.purpose or "block"),
    )


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    try:
        enforcer.unenforce_policy(policy_id)
    except Exception as exc:
        logger.error("Unenforcement failed for %r: %s", policy_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove firewall rules: {exc}",
        ) from exc

    db.delete(policy)
    db.commit()


@router.patch("/{policy_id}/toggle", response_model=PolicyResponse)
def toggle_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )

    policy.is_active = not policy.is_active
    db.commit()
    db.refresh(policy)

    try:
        if policy.is_active and policy.conditions and policy.purpose:
            result = enforcer.enforce_policy(policy.id, policy.purpose, policy.conditions)
            logger.info("Toggle ON %r: %s", policy.name, result)
        else:
            enforcer.unenforce_policy(policy.id)
            logger.info("Toggle OFF %r", policy.name)
    except Exception as exc:
        logger.error("Toggle enforcement failed for %r: %s", policy.name, exc)

    return PolicyResponse.model_validate(policy)


@router.post("/parse", response_model=NLPPolicyParseResponse)
def parse_natural_language_policy(
    nlp_request: NLPPolicyParse,
    current_user: User = Depends(get_current_user),
):
    text = (nlp_request.natural_language or nlp_request.input or "").strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Natural language input is required",
        )

    parsed = _parser.parse(text)
    logger.info(
        "[PolicyEngine] Parse request: purpose=%s domains=%s ips=%s time_range=%s auto_expire=%s",
        parsed.purpose,
        parsed.domains,
        parsed.ips,
        parsed.time_range,
        parsed.auto_expire,
    )
    conditions = _parsed_to_conditions(parsed)
    capabilities = _capabilities_for(parsed)

    action_words = {
        "block": "Block",
        "unblock": "Allow",
        "monitor": "Monitor",
        "alert": "Alert on",
        "isolate": "Isolate",
        "rate_limit": "Rate-limit",
    }
    action_word = action_words.get(parsed.purpose, "Block")

    return NLPPolicyParseResponse(
        name=f"{action_word}: {text[:60]}",
        description=text,
        purpose=parsed.purpose,
        parsed=conditions,
        confidence=round(parsed.confidence, 2),
        explanation=parsed.explanation,
        rule_type=_rule_type_for(parsed),
        capabilities_used=capabilities,
    )
