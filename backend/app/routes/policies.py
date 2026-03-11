import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.policy import Policy
from app.models.user import User
from app.schemas.policy import (
    NLPPolicyParse,
    NLPPolicyParseResponse,
    PolicyCreate,
    PolicyResponse,
)
from app.services.enforcer import enforcer
from ml.enforcer.nlp_parser import NLPPolicyParser, ParsedPolicy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/policies", tags=["Policies"])
_parser = NLPPolicyParser()


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
