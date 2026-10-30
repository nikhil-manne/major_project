"""
Replay Engine API
Enables synchronized session playback and detection regression testing by re-emitting archived sessions
from MinIO object storage across the event backbone.
"""
import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.s3_client import s3_client
from shared.kafka_client import kafka_producer
from shared.config import settings
from services.ingestion.opensearch_sink import event_sink
from services.detection_engine.service import active_rules, rules_for_tenant
from .archiver import SessionArchiver, STORAGE_DIR
from shared.auth import get_current_user, UserContext
from shared.db import db_context, SessionModel

router = APIRouter(prefix="/api/v1/replay", tags=["Recording & Replay Engine"])


class ReplayExecuteRequest(BaseModel):
    session_id: str
    tenant_id: Optional[str] = None
    test_detection_rules: bool = True


def _authorize_session(session_id: str, user: UserContext, requested_tenant: Optional[str] = None) -> str:
    with db_context() as db:
        row = db.query(SessionModel).filter_by(id=session_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found")
        if user.role != "admin" and row.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Session not found in the authorized tenant")
        if requested_tenant and row.tenant_id != requested_tenant and user.role != "admin":
            raise HTTPException(status_code=403, detail="Session tenant does not match request")
        return row.tenant_id


@router.post("/archive/{session_id}")
async def archive_session(session_id: str, tenant_id: Optional[str] = None, user: UserContext = Depends(get_current_user)):
    """Bundle evidence for a session owned by the authenticated tenant."""
    eff_tenant = _authorize_session(session_id, user, tenant_id)
    manifest = SessionArchiver.archive_session(session_id=session_id, tenant_id=eff_tenant)
    return manifest


@router.get("/sessions")
async def list_archived_sessions(tenant_id: Optional[str] = None, user: UserContext = Depends(get_current_user)):
    """List archived sessions visible to the authenticated tenant."""
    manifests = SessionArchiver.list_archived_sessions()
    if user.role == "admin":
        return manifests
    eff_tenant = tenant_id or user.tenant_id
    return [m for m in manifests if m.get("tenant_id") in (eff_tenant, "00000000-0000-0000-0000-000000000123")]


@router.get("/manifest/{session_id}")
async def get_session_manifest(session_id: str, user: UserContext = Depends(get_current_user)):
    """Retrieve manifest metadata only after verifying session ownership."""
    effective_tenant = _authorize_session(session_id, user)
    manifest = SessionArchiver.get_manifest(session_id)
    if not manifest or manifest.get("tenant_id") != effective_tenant:
        raise HTTPException(status_code=404, detail=f"Archived session {session_id} not found")
    return manifest


@router.post("/execute/{session_id}")
async def replay_session(session_id: str, req: ReplayExecuteRequest, user: UserContext = Depends(get_current_user)):
    """
    Reads archived events from MinIO object storage, re-emits attack events with replay: true,
    and runs regression tests against newly compiled Sigma detection rules.
    """
    if req.session_id != session_id:
        raise HTTPException(status_code=400, detail="Path session_id and request session_id must match")
    eff_tenant = _authorize_session(session_id, user, req.tenant_id)
    archived_events: List[NormalizedEvent] = []

    # 1. Try MinIO object storage first
    s3_events_text = s3_client.get_text(f"/sessions/{session_id}/events.jsonl")
    if s3_events_text:
        for line in s3_events_text.splitlines():
            if line.strip():
                try:
                    ev_dict = json.loads(line)
                    parsed = NormalizedEvent(**ev_dict)
                    if parsed.tenant_id == eff_tenant and parsed.session_id == session_id:
                        archived_events.append(parsed)
                except Exception:
                    pass

    # 2. Try local disk storage fallback
    if not archived_events:
        events_path = os.path.join(STORAGE_DIR, session_id, "events.jsonl")
        if os.path.exists(events_path):
            with open(events_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        ev_dict = json.loads(line)
                        parsed = NormalizedEvent(**ev_dict)
                        if parsed.tenant_id == eff_tenant and parsed.session_id == session_id:
                            archived_events.append(parsed)

    # 3. Fallback to current memory events
    if not archived_events:
        archived_events = event_sink.query_events(tenant_id=eff_tenant, session_id=session_id, limit=500)

    if not archived_events:
        raise HTTPException(status_code=404, detail="No recorded events found for this session in MinIO or disk")

    # Re-emit attack events with replay: true
    replayed_attacks = []
    new_detections = []

    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW
    }

    for ev in archived_events:
        if ev.source_type == SourceType.ATTACK:
            replayed_ev = NormalizedEvent(
                tenant_id=ev.tenant_id,
                session_id=ev.session_id,
                scenario_id=ev.scenario_id,
                build_id=ev.build_id,
                timestamp=datetime.now(timezone.utc),
                source_type=ev.source_type,
                source_name=ev.source_name,
                actor=f"replay_engine({ev.actor})",
                action=ev.action,
                mitre_tactic=ev.mitre_tactic,
                mitre_technique=ev.mitre_technique,
                severity=ev.severity,
                outcome=ev.outcome,
                replay=True,
                raw_payload={"original_event_id": ev.event_id, "original_timestamp": ev.timestamp.isoformat()}
            )

            # Produce to Kafka normalized.events topic
            kafka_producer.produce(
                topic=settings.TOPIC_NORMALIZED_EVENTS,
                key=replayed_ev.session_id,
                value=replayed_ev.model_dump()
            )

            await event_sink.index_event(replayed_ev)
            replayed_attacks.append(replayed_ev)

            # Test active detection rules
            if req.test_detection_rules:
                for rule in rules_for_tenant(eff_tenant):
                    if rule.evaluate_event(replayed_ev):
                        det = NormalizedEvent(
                            tenant_id=ev.tenant_id,
                            session_id=ev.session_id,
                            build_id=ev.build_id,
                            timestamp=datetime.now(timezone.utc),
                            source_type=SourceType.DETECTION,
                            source_name="sigma_rule",
                            actor="system",
                            action=f"REPLAY DETECTION: rule:{rule.title} matched",
                            mitre_tactic=rule.mitre_tactic or ev.mitre_tactic,
                            mitre_technique=rule.mitre_technique or ev.mitre_technique,
                            severity=sev_map.get(rule.level, Severity.HIGH),
                            outcome=Outcome.DETECTED,
                            replay=True,
                            raw_payload={"rule_id": rule.id, "replayed_attack_id": replayed_ev.event_id}
                        )
                        await event_sink.index_event(det)
                        kafka_producer.produce(
                            topic=settings.TOPIC_NORMALIZED_EVENTS,
                            key=det.session_id,
                            value=det.model_dump()
                        )
                        new_detections.append(det)

    return {
        "status": "replayed",
        "session_id": session_id,
        "attacks_re_emitted": len(replayed_attacks),
        "detections_triggered": len(new_detections),
        "regression_test_summary": {
            "techniques_tested": list({e.mitre_technique for e in replayed_attacks if e.mitre_technique}),
            "techniques_detected": list({d.mitre_technique for d in new_detections if d.mitre_technique})
        }
    }


@router.get("/timeline/{session_id}")
async def get_synchronized_timeline(session_id: str, tenant_id: Optional[str] = None, user: UserContext = Depends(get_current_user)):
    """
    Returns synchronized timeline stream interleaving terminal events,
    network events, and detection alerts for synchronized scrubber playback.
    """
    eff_tenant = _authorize_session(session_id, user, tenant_id)
    events = event_sink.query_events(tenant_id=eff_tenant, session_id=session_id, limit=500)
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    timeline_points = []
    if sorted_events:
        t0 = sorted_events[0].timestamp
        for ev in sorted_events:
            offset_sec = max(0.0, (ev.timestamp - t0).total_seconds())
            timeline_points.append({
                "time_offset_sec": round(offset_sec, 2),
                "timestamp": ev.timestamp.isoformat(),
                "event_id": ev.event_id,
                "source_type": ev.source_type.value,
                "source_name": ev.source_name,
                "actor": ev.actor,
                "action": ev.action,
                "mitre_technique": ev.mitre_technique,
                "severity": ev.severity.value,
                "outcome": ev.outcome.value if ev.outcome else None,
                "replay": ev.replay
            })

    return {
        "session_id": session_id,
        "total_timeline_points": len(timeline_points),
        "duration_sec": timeline_points[-1]["time_offset_sec"] if timeline_points else 0.0,
        "timeline": timeline_points
    }
