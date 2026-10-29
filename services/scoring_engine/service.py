"""
Scoring Engine & SOC Incident Management API
Calculates weighted Security Readiness Scores, persists them to PostgreSQL,
and provides database-backed SOC case management and threat hunting.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome, ReadinessScoreReport
from shared.db import get_db, IncidentModel, ReadinessScoreModel, db_context
from shared.auth import get_current_user, require_roles, UserContext
from services.ingestion.opensearch_sink import event_sink
from services.validation_engine.navigator import ValidationEngine

logger = logging.getLogger("cyberrange.scoring")

router = APIRouter(prefix="/api/v1/scoring", tags=["Security Readiness Scoring & SOC"])


class IncidentUpdateRequest(BaseModel):
    status: str = Field(..., description="open | investigating | contained | resolved | false_positive")
    analyst_notes: Optional[str] = None
    assigned_to: Optional[str] = None


class ThreatHuntQuery(BaseModel):
    query_text: str = Field(..., min_length=1, max_length=500)
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None


class IncidentDBProxy(dict):
    """Backwards-compatible dict proxy backed by PostgreSQL incidents table."""
    def get(self, key: str, default=None):
        try:
            with db_context() as db:
                inc = db.query(IncidentModel).filter_by(id=key).first()
                if inc:
                    return {
                        "incident_id": inc.id,
                        "tenant_id": inc.tenant_id,
                        "session_id": inc.session_id,
                        "title": inc.title,
                        "mitre_technique": inc.mitre_technique,
                        "severity": inc.severity,
                        "status": inc.status,
                        "assigned_to": inc.assigned_to,
                        "created_at": inc.created_at.isoformat() if inc.created_at else "",
                        "analyst_notes": inc.analyst_notes,
                        "triggering_event": inc.triggering_event or {}
                    }
                return default
        except Exception:
            return default

    def values(self):
        try:
            with db_context() as db:
                incs = db.query(IncidentModel).all()
                return [
                    {
                        "incident_id": inc.id,
                        "tenant_id": inc.tenant_id,
                        "session_id": inc.session_id,
                        "title": inc.title,
                        "mitre_technique": inc.mitre_technique,
                        "severity": inc.severity,
                        "status": inc.status,
                        "assigned_to": inc.assigned_to,
                        "created_at": inc.created_at.isoformat() if inc.created_at else "",
                        "analyst_notes": inc.analyst_notes,
                        "triggering_event": inc.triggering_event or {}
                    }
                    for inc in incs
                ]
        except Exception:
            return []


incidents_db = IncidentDBProxy()


@router.get("/score", response_model=ReadinessScoreReport)
async def calculate_readiness_score(
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    build_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user),
):
    """
    Computes weighted Security Readiness Score based on:
    - MITRE coverage percentage (50% weight)
    - Detection latency (25% weight)
    - Unresolved incidents penalty (25% weight)
    Persists computation to PostgreSQL readiness_scores table.
    """
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot calculate a score for another tenant")
    events = event_sink.query_events(tenant_id=eff_tenant, session_id=session_id, build_id=build_id, limit=1000)
    cov = ValidationEngine.calculate_coverage(events)

    coverage_pct = cov.get("coverage_percentage", 0.0)

    # Calculate average detection latency from covered techniques
    latencies = [t["latency_sec"] for t in cov.get("techniques", []) if t["latency_sec"] is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 30.0

    latency_score = max(10.0, 100.0 - (avg_latency * 1.5))

    # Unresolved incidents from database
    unresolved = 0
    try:
        def check_unresolved(session_obj):
            return session_obj.query(IncidentModel).filter(
                IncidentModel.tenant_id == eff_tenant,
                IncidentModel.status.in_(["open", "investigating"])
            ).count()

        if db:
            unresolved = check_unresolved(db)
        else:
            with db_context() as s:
                unresolved = check_unresolved(s)
    except Exception:
        unresolved = 0

    incident_score = max(0.0, 100.0 - (unresolved * 15.0))

    w_coverage = 0.50
    w_latency = 0.25
    w_incident = 0.25

    final_score = round(
        (coverage_pct * w_coverage) +
        (latency_score * w_latency) +
        (incident_score * w_incident),
        1
    )

    grade = "F"
    if final_score >= 90:
        grade = "A"
    elif final_score >= 75:
        grade = "B"
    elif final_score >= 60:
        grade = "C"

    breakdown_data = {
        "grade": grade,
        "tested_techniques": cov.get("tested_techniques", 0),
        "covered_count": cov.get("covered_count", 0),
        "gap_count": cov.get("gap_count", 0),
        "latency_score": round(latency_score, 1),
        "incident_score": round(incident_score, 1),
        # This is a lab heuristic only. Do not represent it as production certification.
        "heuristic_threshold_met": final_score >= 75.0 and cov.get("gap_count", 0) == 0,
        "ready_for_production": False,
        "production_readiness_verified": False,
        "interpretation": "Heuristic score for this limited test dataset; not a production security certification."
    }

    report = ReadinessScoreReport(
        session_id=session_id,
        build_id=build_id,
        tenant_id=eff_tenant,
        coverage_pct=coverage_pct,
        avg_detection_latency_sec=round(avg_latency, 2),
        unresolved_incidents=unresolved,
        score=final_score,
        computed_at=datetime.now(timezone.utc),
        breakdown=breakdown_data
    )

    # Persist in DB
    try:
        def save_score(session_obj):
            model = ReadinessScoreModel(
                id=str(uuid.uuid4()),
                session_id=session_id,
                build_id=build_id,
                tenant_id=eff_tenant,
                coverage_pct=coverage_pct,
                avg_detection_latency_sec=round(avg_latency, 2),
                unresolved_incidents=unresolved,
                score=final_score,
                breakdown=breakdown_data,
                computed_at=datetime.now(timezone.utc)
            )
            session_obj.add(model)
            session_obj.commit()

        if db:
            save_score(db)
        else:
            with db_context() as s:
                save_score(s)
    except Exception as e:
        logger.debug(f"Could not persist readiness score: {e}")

    return report


# --- SOC Incidents & Triage backed by PostgreSQL ---

@router.get("/incidents")
async def list_incidents(
    tenant_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user),
):
    """List all SOC security incidents and cases from PostgreSQL."""
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot list incidents for another tenant")
    incidents = db.query(IncidentModel).filter_by(tenant_id=eff_tenant).all()

    # Auto-populate incidents from critical/high detection alerts if table is empty
    if not incidents:
        alerts = event_sink.query_events(tenant_id=eff_tenant, source_type="detection", limit=50)
        for a in alerts:
            inc_id = f"INC-{a.event_id[:8]}"
            inc_model = IncidentModel(
                id=inc_id,
                tenant_id=a.tenant_id,
                session_id=a.session_id,
                title=a.action,
                mitre_technique=a.mitre_technique,
                severity=a.severity.value,
                status="open",
                assigned_to="soc1",
                created_at=a.timestamp,
                analyst_notes="Automated incident escalated from high-severity detection alert.",
                triggering_event=a.model_dump()
            )
            db.add(inc_model)
        db.commit()
        eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot list incidents for another tenant")
    incidents = db.query(IncidentModel).filter_by(tenant_id=eff_tenant).all()

    return [
        {
            "incident_id": inc.id,
            "tenant_id": inc.tenant_id,
            "session_id": inc.session_id,
            "title": inc.title,
            "mitre_technique": inc.mitre_technique,
            "severity": inc.severity,
            "status": inc.status,
            "assigned_to": inc.assigned_to,
            "created_at": inc.created_at.isoformat() if inc.created_at else "",
            "analyst_notes": inc.analyst_notes,
            "triggering_event": inc.triggering_event or {}
        }
        for inc in incidents
    ]


@router.patch("/incidents/{incident_id}")
async def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_roles(["soc", "admin"]))
):
    """Update SOC incident status, assign analyst, or log triage notes in database."""
    inc = db.query(IncidentModel).filter_by(id=incident_id, tenant_id=user.tenant_id).first()
    if not inc and user.role == "admin":
        inc = db.query(IncidentModel).filter_by(id=incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    allowed_statuses = {"open", "investigating", "contained", "resolved", "false_positive"}
    if req.status not in allowed_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(allowed_statuses)}")
    inc.status = req.status
    if req.analyst_notes:
        inc.analyst_notes = req.analyst_notes
    if req.assigned_to:
        inc.assigned_to = req.assigned_to

    db.commit()
    db.refresh(inc)

    # Emit audit event
    audit = NormalizedEvent(
        tenant_id=inc.tenant_id,
        session_id=inc.session_id,
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.SOC_ACTION,
        source_name="analyst",
        actor=user.username or req.assigned_to or "soc_analyst",
        action=f"Incident {incident_id} transitioned to '{req.status}'",
        severity=Severity.LOW,
        outcome=Outcome.SUCCEEDED,
        raw_payload={"incident_id": incident_id, "notes": req.analyst_notes}
    )
    await event_sink.index_event(audit)

    return {
        "incident_id": inc.id,
        "tenant_id": inc.tenant_id,
        "session_id": inc.session_id,
        "title": inc.title,
        "mitre_technique": inc.mitre_technique,
        "severity": inc.severity,
        "status": inc.status,
        "assigned_to": inc.assigned_to,
        "created_at": inc.created_at.isoformat() if inc.created_at else "",
        "analyst_notes": inc.analyst_notes,
        "triggering_event": inc.triggering_event or {}
    }


@router.post("/hunt")
async def threat_hunting_query(query: ThreatHuntQuery, user: UserContext = Depends(get_current_user)):
    """Search for IOCs only in the authenticated tenant's event stream."""
    if query.tenant_id and query.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot hunt through another tenant's events")
    eff_tenant = query.tenant_id if (query.tenant_id and user.role == "admin") else user.tenant_id
    all_events = event_sink.query_events(tenant_id=eff_tenant, session_id=query.session_id, limit=1000)
    q = query.query_text.lower()
    matches = []

    for ev in all_events:
        searchable = f"{ev.action} {ev.source_name} {ev.actor} {ev.mitre_technique or ''} {str(ev.raw_payload)}".lower()
        if q in searchable:
            matches.append(ev)

    return {
        "query": query.query_text,
        "matches_count": len(matches),
        "results": matches
    }
