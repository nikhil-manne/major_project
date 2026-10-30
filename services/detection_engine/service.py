"""
Blue Team Detection Engine Service
Manages Sigma detection rules with PostgreSQL persistence, continuously evaluates events
as a Kafka consumer of 'normalized.events', and emits live security alerts.
"""
import asyncio
import json
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.db import get_db, SigmaRuleModel, Lab, SessionModel, db_context
from shared.auth import get_current_user, require_roles, UserContext
from shared.kafka_client import KafkaConsumerBase, kafka_producer
from shared.config import settings
from services.ingestion.opensearch_sink import event_sink
from .sigma_compiler import SigmaEngine, CompiledSigmaRule

logger = logging.getLogger("cyberrange.detection")

router = APIRouter(prefix="/api/v1/detection", tags=["Blue Team Detection Engine"])

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

# Active compiled rules registry in memory for high-performance matching
active_rules: Dict[str, CompiledSigmaRule] = {}  # Shared, repository-bundled rules only
tenant_active_rules: Dict[str, Dict[str, CompiledSigmaRule]] = {}


def rules_for_tenant(tenant_id: str) -> List[CompiledSigmaRule]:
    tenant_rules = tenant_active_rules.get(tenant_id, {})
    # Deduplicate rules by ID: custom tenant rules take precedence over bundled rules
    seen: Dict[str, CompiledSigmaRule] = {}
    for r in list(active_rules.values()) + list(tenant_rules.values()):
        seen[r.id] = r
    # Prioritize higher severity rules
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(seen.values(), key=lambda r: sev_order.get(r.level.lower(), 4))


def load_default_rules():
    """Loads default Sigma rules from filesystem rules/ directory."""
    active_rules.clear()
    if not os.path.exists(RULES_DIR):
        return
    for f in os.listdir(RULES_DIR):
        if f.endswith(".yaml") or f.endswith(".yml"):
            path = os.path.join(RULES_DIR, f)
            try:
                with open(path, "r", encoding="utf-8") as rf:
                    content = rf.read()
                    rule = SigmaEngine.load_rule_from_yaml(content)
                    active_rules[rule.id] = rule
            except Exception:
                pass


# Load rules on module import
load_default_rules()


class CreateRuleRequest(BaseModel):
    sigma_yaml: str
    tenant_id: Optional[str] = None
    created_by: str = "blue1"


class EvaluateRequest(BaseModel):
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None


# --- Real Kafka Consumer for normalized.events ---

class KafkaDetectionConsumer:
    """
    Subscribes to 'normalized.events' Kafka topic, matching incoming events
    against active Sigma rules in real-time.
    """
    def __init__(self):
        self.running = False
        self.task = None

    async def run(self):
        consumer = KafkaConsumerBase(
            topics=[settings.TOPIC_NORMALIZED_EVENTS],
            group_id="detection-engine-evaluator"
        )
        self.running = True
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW
        }

        while self.running:
            try:
                msg = consumer.poll_message(timeout=0.5)
                if msg:
                    # Ignore detection events to prevent detection feedback loops
                    if msg.get("source_type") != "detection":
                        norm_event = NormalizedEvent(**msg)
                        tenant_rules = rules_for_tenant(norm_event.tenant_id)
                        for rule in tenant_rules:
                            if rule.evaluate_event(norm_event):
                                det_event = NormalizedEvent(
                                    tenant_id=norm_event.tenant_id,
                                    session_id=norm_event.session_id,
                                    scenario_id=norm_event.scenario_id,
                                    build_id=norm_event.build_id,
                                    timestamp=datetime.now(timezone.utc),
                                    source_type=SourceType.DETECTION,
                                    source_name="sigma_rule",
                                    actor="system",
                                    action=f"rule:{rule.title} matched",
                                    mitre_tactic=rule.mitre_tactic or norm_event.mitre_tactic,
                                    mitre_technique=rule.mitre_technique or norm_event.mitre_technique,
                                    severity=sev_map.get(rule.level, Severity.HIGH),
                                    outcome=Outcome.DETECTED,
                                    replay=norm_event.replay,
                                    raw_payload={
                                        "rule_id": rule.id,
                                        "rule_title": rule.title,
                                        "triggering_event_id": norm_event.event_id,
                                        "matched_action": norm_event.action
                                    }
                                )
                                # Index detection and re-publish to normalized.events
                                await event_sink.index_event(det_event)
                                kafka_producer.produce(
                                    topic=settings.TOPIC_NORMALIZED_EVENTS,
                                    key=det_event.session_id,
                                    value=det_event.model_dump()
                                )
                                break
            except Exception:
                pass
            await asyncio.sleep(0.1)

        consumer.close()

    def start(self):
        if not self.task or self.task.done():
            self.task = asyncio.create_task(self.run())

    def stop(self):
        self.running = False


detection_worker = KafkaDetectionConsumer()


# --- API Routes ---

@router.get("/rules")
async def list_rules(db: Session = Depends(get_db), user: UserContext = Depends(get_current_user)):
    """List bundled rules and only the authenticated tenant's custom rules."""
    response = []
    for rule in active_rules.values():
        response.append({"id": rule.id, "title": rule.title, "description": rule.description, "level": rule.level, "mitre_technique": rule.mitre_technique, "mitre_tactic": rule.mitre_tactic, "sigma_yaml": rule.raw_yaml, "compiled_query": rule.compiled_query, "scope": "bundled"})
    try:
        db_rules = db.query(SigmaRuleModel).filter_by(tenant_id=user.tenant_id).all()
        for row in db_rules:
            try:
                compiled = SigmaEngine.load_rule_from_yaml(row.sigma_yaml)
                tenant_active_rules.setdefault(user.tenant_id, {})[compiled.id] = compiled
                stored_query = row.compiled_query
                if isinstance(stored_query, str):
                    try:
                        stored_query = json.loads(stored_query)
                    except (json.JSONDecodeError, TypeError):
                        stored_query = None
                response.append({"id": compiled.id, "title": compiled.title, "description": compiled.description, "level": compiled.level, "mitre_technique": compiled.mitre_technique, "mitre_tactic": compiled.mitre_tactic, "sigma_yaml": row.sigma_yaml, "compiled_query": stored_query, "scope": "tenant"})
            except Exception:
                logger.exception("Could not compile stored tenant detection rule %s", row.id)
    except Exception:
        logger.exception("Could not query tenant detection rules")
    return response


@router.post("/rules")
async def add_or_update_rule(
    req: CreateRuleRequest,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_roles(["blue", "admin"]))
):
    """Validate, register, and persist a new Sigma detection rule in PostgreSQL."""
    val = SigmaEngine.validate_sigma_syntax(req.sigma_yaml)
    if not val["valid"]:
        raise HTTPException(status_code=400, detail=val["error"])

    if req.tenant_id and req.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot create a rule for another tenant")
    rule = SigmaEngine.load_rule_from_yaml(req.sigma_yaml)
    rule_tenant = req.tenant_id if (req.tenant_id and user.role == "admin") else user.tenant_id
    stored_id = f"{rule_tenant}:{rule.id}"

    # Persist under a tenant-qualified key so same-named rules cannot overwrite other tenants.
    try:
        existing = db.query(SigmaRuleModel).filter_by(id=stored_id, tenant_id=rule_tenant).first()
        if existing:
            existing.name = rule.title
            existing.mitre_technique = rule.mitre_technique or "T1059"
            existing.sigma_yaml = req.sigma_yaml
            existing.compiled_query = json.dumps(rule.compiled_query, sort_keys=True)
        else:
            db_rule = SigmaRuleModel(
                id=stored_id,
                tenant_id=rule_tenant,
                name=rule.title,
                mitre_technique=rule.mitre_technique or "T1059",
                sigma_yaml=req.sigma_yaml,
                compiled_query=json.dumps(rule.compiled_query, sort_keys=True),
                created_by=user.user_id,
                created_at=datetime.now(timezone.utc)
            )
            db.add(db_rule)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception("Failed to persist Sigma rule; rule was not activated")
        raise HTTPException(status_code=503, detail="Rule could not be persisted; it was not activated") from e

    tenant_active_rules.setdefault(rule_tenant, {})[rule.id] = rule

    return {
        "status": "active",
        "rule_id": rule.id,
        "title": rule.title,
        "technique": rule.mitre_technique,
        "compiled_query": rule.compiled_query,
        "tenant_id": rule_tenant,
        "scope": "tenant"
    }


@router.post("/rules/validate")
async def validate_rule(req: CreateRuleRequest):
    """Test validity of a draft Sigma YAML rule before saving."""
    return SigmaEngine.validate_sigma_syntax(req.sigma_yaml)


@router.post("/evaluate")
async def evaluate_detection_rules(req: EvaluateRequest, user: UserContext = Depends(get_current_user)):
    """
    Evaluates active Sigma rules against recent events for a session,
    emitting at most one detection alert per triggering attack event.
    """
    if req.tenant_id and req.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot evaluate events for another tenant")
    eff_tenant = req.tenant_id if (req.tenant_id and user.role == "admin") else user.tenant_id
    events = event_sink.query_events(tenant_id=eff_tenant, session_id=req.session_id, limit=500)

    # Track triggering event IDs that have already generated a detection alert
    already_detected = set()
    for ev in events:
        if ev.source_type == SourceType.DETECTION and ev.raw_payload:
            trig_id = ev.raw_payload.get("triggering_event_id")
            if trig_id:
                already_detected.add(trig_id)

    detections_generated: List[NormalizedEvent] = []
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW
    }

    # Evaluate events in chronological order
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    for event in sorted_events:
        if event.source_type == SourceType.DETECTION:
            continue
        if event.event_id in already_detected:
            continue

        for rule in rules_for_tenant(eff_tenant):
            if rule.evaluate_event(event):
                det_event = NormalizedEvent(
                    tenant_id=event.tenant_id,
                    session_id=event.session_id,
                    scenario_id=event.scenario_id,
                    build_id=event.build_id,
                    timestamp=datetime.now(timezone.utc),
                    source_type=SourceType.DETECTION,
                    source_name="sigma_rule",
                    actor="system",
                    action=f"rule:{rule.title} matched",
                    mitre_tactic=rule.mitre_tactic or event.mitre_tactic,
                    mitre_technique=rule.mitre_technique or event.mitre_technique,
                    severity=sev_map.get(rule.level, Severity.HIGH),
                    outcome=Outcome.DETECTED,
                    provenance=getattr(event, "provenance", "simulated"),
                    replay=event.replay,
                    raw_payload={
                        "rule_id": rule.id,
                        "rule_title": rule.title,
                        "triggering_event_id": event.event_id,
                        "matched_action": event.action,
                        "provenance": getattr(event, "provenance", "simulated")
                    }
                )
                await event_sink.index_event(det_event)
                detections_generated.append(det_event)
                already_detected.add(event.event_id)
                break  # Each attack event produces at most one detection alert

    return {
        "session_id": req.session_id,
        "events_evaluated": len(events),
        "detections_fired": len(detections_generated),
        "detections": detections_generated
    }


@router.get("/vulnerabilities")
async def get_vulnerability_queue(
    tenant_id: Optional[str] = None,
    lab_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user),
):
    """
    Exposes static configuration and container image vulnerability findings
    as a dedicated Blue Team vulnerability queue with source evidence and image digests.
    """
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot query vulnerabilities for another tenant")

    query = db.query(Lab).filter(Lab.status != "archived")
    if user.role != "admin":
        query = query.filter((Lab.tenant_id == eff_tenant) | (Lab.is_demo == 1))
    if lab_id:
        query = query.filter(Lab.id == lab_id)

    labs = query.all()
    queue = []
    for lab in labs:
        # 1. Image vulnerability findings
        vuln_data = getattr(lab, "vulnerability_scan_result", {}) or {}
        vulns = vuln_data.get("vulnerabilities", [])
        for v in vulns:
            queue.append({
                "type": "image_cve",
                "lab_id": lab.id,
                "lab_name": lab.name,
                "target_image": lab.image_tag or lab.image_digest or "unknown",
                "image_digest": lab.image_digest,
                "cve_id": v.get("cve_id", "CVE-UNKNOWN"),
                "package": v.get("package", "unknown"),
                "installed_version": v.get("installed_version", ""),
                "fixed_version": v.get("fixed_version", "N/A"),
                "severity": v.get("severity", "MEDIUM"),
                "title": v.get("title", ""),
                "evidence_source": v.get("evidence_source", "trivy_cli"),
                "scanned_at": vuln_data.get("scanned_at")
            })

        # 2. Static configuration findings
        safety = lab.safety_scan_result or {}
        findings = safety.get("findings", [])
        for f in findings:
            queue.append({
                "type": "configuration_policy",
                "lab_id": lab.id,
                "lab_name": lab.name,
                "target_image": lab.image_tag or "Dockerfile/Compose",
                "image_digest": lab.image_digest,
                "cve_id": f.get("rule", "POLICY"),
                "package": f.get("service") or "config",
                "installed_version": f"Line {f.get('line', 1)}",
                "fixed_version": "N/A",
                "severity": f.get("severity", "MEDIUM"),
                "title": f.get("message", ""),
                "evidence_source": safety.get("engine", "policy_scanner"),
                "scanned_at": lab.created_at.isoformat() if lab.created_at else None
            })
    return queue


@router.get("/sensor-health")
async def get_sensor_health(user: UserContext = Depends(get_current_user)):
    """Reports status of telemetry collectors, event pipeline, and sensor sidecars."""
    from services.orchestrator.k8s_client import k8s_client
    from shared.kafka_client import kafka_producer
    return {
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sensors": {
            "kafka_event_backbone": {
                "connected": getattr(kafka_producer, "_connected", False),
                "broker": settings.KAFKA_BOOTSTRAP_SERVERS,
                "mode": "live" if getattr(kafka_producer, "_connected", False) else "fallback_sink"
            },
            "opensearch_sink": {
                "connected": event_sink.is_opensearch_live,
                "host": settings.OPENSEARCH_HOST,
                "mode": "opensearch" if event_sink.is_opensearch_live else "relational_fallback"
            },
            "kubernetes_cluster": {
                "connected": k8s_client.is_connected,
                "mode": "live" if k8s_client.is_connected else "simulated"
            },
            "falco_runtime_sensor": {
                "enabled": k8s_client.is_connected,
                "status": "active" if k8s_client.is_connected else "simulated"
            },
            "suricata_network_sensor": {
                "enabled": k8s_client.is_connected,
                "status": "active" if k8s_client.is_connected else "simulated"
            },
            "tcpdump_pcap_sensor": {
                "enabled": k8s_client.is_connected,
                "status": "active" if k8s_client.is_connected else "simulated"
            }
        }
    }


@router.get("/alerts")
async def get_alerts(
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = 100,
    user: UserContext = Depends(get_current_user),
):
    """Fetch detection alerts within the authenticated tenant, deduplicated per triggering event."""
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot query alerts for another tenant")
    raw_alerts = event_sink.query_events(
        tenant_id=eff_tenant,
        session_id=session_id,
        source_type="detection",
        limit=limit
    )
    seen_triggers = set()
    deduped = []
    for a in raw_alerts:
        trig = a.raw_payload.get("triggering_event_id") if a.raw_payload else None
        if trig:
            if trig in seen_triggers:
                continue
            seen_triggers.add(trig)
        deduped.append(a)
    return deduped
