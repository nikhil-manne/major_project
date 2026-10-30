"""
Sandbox Orchestrator Service
Manages ephemeral session isolation, Kubernetes manifests, PostgreSQL persistence, and TTL lifecycle.
"""
import asyncio
from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.db import get_db, SessionModel, db_context, Lab
from shared.auth import get_current_user, require_roles, UserContext
from shared.config import settings
from services.ingestion.opensearch_sink import event_sink
from .scanner import SafetyScanner
from .k8s_client import k8s_client

logger = logging.getLogger("cyberrange.orchestrator")

router = APIRouter(prefix="/api/v1/sessions", tags=["Sandbox Orchestration"])


class CreateSessionRequest(BaseModel):
    tenant_id: Optional[str] = None
    lab_id: Optional[str] = None
    target_image: str = "vulnerable-web:latest"
    build_id: Optional[str] = None
    ttl_minutes: int = Field(default=30, ge=5, le=240)
    dockerfile_content: Optional[str] = None
    skip_safety_gate: bool = False


class SessionInfo(BaseModel):
    session_id: str
    tenant_id: str
    lab_id: Optional[str] = None
    build_id: Optional[str] = None
    target_image: str
    target_endpoint: Optional[str] = None
    execution_mode: Optional[str] = "simulated"
    namespace: str
    status: str  # creating | active | destroyed
    created_at: datetime
    expires_at: Optional[datetime] = None
    destroyed_at: Optional[datetime] = None
    isolation: Dict[str, Any]
    safety_scan: Optional[Dict[str, Any]] = None
    archive_path: Optional[str] = None


def to_session_info(s: SessionModel) -> SessionInfo:
    return SessionInfo(
        session_id=s.id,
        tenant_id=s.tenant_id,
        lab_id=s.lab_id,
        build_id=s.build_id,
        target_image=s.target_image,
        target_endpoint=getattr(s, "target_endpoint", None),
        execution_mode=getattr(s, "execution_mode", "simulated"),
        namespace=s.namespace,
        status=s.status,
        created_at=s.created_at,
        expires_at=s.expires_at,
        destroyed_at=s.destroyed_at,
        isolation=s.isolation or {},
        safety_scan=s.safety_scan,
        archive_path=s.archive_path
    )


class SessionDBProxy(dict):
    """Transparent dictionary proxy backed by PostgreSQL for backwards-compatibility."""
    def get(self, key: str, default=None):
        try:
            with db_context() as db:
                row = db.query(SessionModel).filter_by(id=key).first()
                return to_session_info(row) if row else default
        except Exception:
            return default

    def __getitem__(self, key: str):
        res = self.get(key)
        if res is None:
            raise KeyError(key)
        return res

    def values(self):
        try:
            with db_context() as db:
                rows = db.query(SessionModel).all()
                return [to_session_info(r) for r in rows]
        except Exception:
            return []


sessions_db = SessionDBProxy()


# --- TTL Reaper Background Task ---

async def reap_expired_sessions():
    """Periodically queries database and destroys sessions that have passed their TTL."""
    try:
        now = datetime.now(timezone.utc)
        with db_context() as db:
            expired = db.query(SessionModel).filter(
                SessionModel.status == "active",
                SessionModel.expires_at != None,
                SessionModel.expires_at <= now
            ).all()

            for s in expired:
                logger.info(f"TTL expired for session {s.id}. Tearing down sandbox...")
                s.status = "destroyed"
                s.destroyed_at = now
                k8s_client.delete_sandbox(s.id)

                # Emit audit event
                teardown_event = NormalizedEvent(
                    tenant_id=s.tenant_id,
                    session_id=s.id,
                    build_id=s.build_id,
                    timestamp=now,
                    source_type=SourceType.SOC_ACTION,
                    source_name="ttl_reaper",
                    actor="system",
                    action=f"Auto-destroyed expired session '{s.id}' via TTL policy",
                    severity=Severity.LOW,
                    outcome=Outcome.SUCCEEDED
                )
                await event_sink.index_event(teardown_event)

            if expired:
                db.commit()
    except Exception as e:
        logger.debug(f"TTL Reaper check exception: {e}")


@router.post("", response_model=SessionInfo)
async def create_session(
    req: CreateSessionRequest,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user)
):
    """
    Creates an isolated sandbox environment for testing a build or image.
    Applies safety scanning, provisions the isolated Kubernetes namespace,
    and persists record to the PostgreSQL database.
    """
    # Tenant scope comes from the verified identity; clients cannot select another tenant.
    if req.tenant_id and req.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You cannot create a session for another tenant")
    effective_tenant = req.tenant_id if (req.tenant_id and user.role == "admin") else user.tenant_id
    if req.skip_safety_gate and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only an admin may override the safety gate")

    target_image = req.target_image
    if req.lab_id:
        lab_row = db.query(Lab).filter_by(id=req.lab_id).first()
        if not lab_row or lab_row.status == "archived":
            raise HTTPException(status_code=404, detail="Lab not found or is archived")
        if user.role != "admin" and lab_row.tenant_id != user.tenant_id and not getattr(lab_row, "is_demo", 0):
            raise HTTPException(status_code=404, detail="Lab not found")
        # Ensure only built labs with real image artifact can be launched
        if lab_row.status in ("policy_checked", "uploaded", "failed", "building", "build_failed", "pending") or not lab_row.image_tag:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot launch session: Lab '{lab_row.name}' has status '{lab_row.status}' and has not been built into an image artifact."
            )
        # Use verified image artifact from the lab record
        target_image = lab_row.image_digest or lab_row.image_tag

    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    namespace = f"sandbox-{session_id}"

    # Dockerfile content is not an image. This version does not contain an isolated builder;
    # never deploy a separately supplied image tag while implying it was built from this file.
    if req.dockerfile_content and settings.ATTACK_EXECUTION_MODE.lower() == "live":
        raise HTTPException(status_code=409, detail={
            "message": "Live deployment from uploaded Dockerfiles is not implemented: no isolated image builder is configured.",
            "dockerfile_executed": False,
            "next_step": "Build and scan the image in a separately isolated builder, then deploy the verified image digest."
        })

    # 1. Safety Scanning
    safety_scan = None
    if req.dockerfile_content:
        safety_scan = SafetyScanner.lint_dockerfile(req.dockerfile_content)
        if not safety_scan["passed"] and not req.skip_safety_gate:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Dockerfile failed pre-deployment security gate",
                    "scan_results": safety_scan
                }
            )
    else:
        safety_scan = SafetyScanner.scan_image(target_image)
        if settings.ATTACK_EXECUTION_MODE.lower() == "live" and not safety_scan.get("verified", False) and not req.skip_safety_gate:
            raise HTTPException(status_code=503, detail={
                "message": "Live session creation requires a successful real Trivy scan.",
                "scan_results": safety_scan,
            })

    # 2. Kubernetes Sandbox Provisioning
    k8s_result = k8s_client.create_sandbox(
        session_id=session_id,
        tenant_id=effective_tenant,
        target_image=target_image
    )
    if k8s_result.get("execution_mode") == "failed":
        raise HTTPException(status_code=503, detail={
            "message": "Sandbox provisioning failed; no session was marked active.",
            "provisioning": k8s_result,
        })
    if not k8s_result.get("applied_to_cluster", False):
        if settings.ATTACK_EXECUTION_MODE.lower() == "live" or not settings.ALLOW_SIMULATED_SANDBOX:
            raise HTTPException(status_code=503, detail="A Kubernetes sandbox is required for live sessions")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=req.ttl_minutes)

    live_provisioned = bool(k8s_result.get("applied_to_cluster", False))
    target_endpoint = k8s_result.get("target_endpoint") or (
        f"target-app.{namespace}.svc.cluster.local" if live_provisioned else f"simulated-target.{session_id}.local"
    )
    execution_mode = "live" if live_provisioned else "simulated"

    isolation_spec = {
        "execution_mode": execution_mode,
        "network_policy_enforced": live_provisioned,
        "pod_security_standard": "baseline" if live_provisioned else "not_enforced_simulation",
        "toolbox_allowed": live_provisioned,
        "rootless": False,
        "k8s_provisioned": live_provisioned,
        "target_endpoint": target_endpoint,
        "resources": k8s_result.get("resources", []),
        "planned_resources": k8s_result.get("planned_resources", []),
        "provisioning_note": k8s_result.get("note") or k8s_result.get("error"),
    }

    # 3. PostgreSQL Persistence
    new_session = SessionModel(
        id=session_id,
        tenant_id=effective_tenant,
        lab_id=req.lab_id,
        build_id=req.build_id,
        target_image=target_image,
        target_endpoint=target_endpoint,
        execution_mode=execution_mode,
        namespace=namespace,
        status="active",
        created_at=now,
        expires_at=expires_at,
        destroyed_at=None,
        isolation=isolation_spec,
        safety_scan=safety_scan,
        archive_path=f"/sessions/{session_id}"
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    # 4. Audit normalized event
    audit_event = NormalizedEvent(
        tenant_id=effective_tenant,
        session_id=session_id,
        build_id=req.build_id,
        timestamp=now,
        source_type=SourceType.SOC_ACTION,
        source_name="orchestrator",
        actor=user.username,
        action=f"Created sandbox session '{session_id}' in namespace '{namespace}' (target: {target_image})",
        severity=Severity.LOW,
        outcome=Outcome.SUCCEEDED,
        provenance=execution_mode,
        raw_payload={"isolation": isolation_spec, "ttl_minutes": req.ttl_minutes}
    )
    await event_sink.index_event(audit_event)

    return to_session_info(new_session)


@router.get("", response_model=List[SessionInfo])
async def list_sessions(
    tenant_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user),
):
    """List session metadata only for the authenticated tenant (admins may select a tenant)."""
    await reap_expired_sessions()
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You cannot list sessions for another tenant")
    if user.role == "admin":
        records = db.query(SessionModel).order_by(SessionModel.created_at.desc()).all()
    else:
        records = db.query(SessionModel).filter(
            SessionModel.tenant_id == eff_tenant
        ).order_by(SessionModel.created_at.desc()).all()
    return [to_session_info(s) for s in records]


@router.get("/{session_id}", response_model=SessionInfo)
async def get_session(
    session_id: str, db: Session = Depends(get_db), user: UserContext = Depends(get_current_user)
):
    """Retrieve metadata for a session, strictly scoped by tenant."""
    session_row = db.query(SessionModel).filter_by(id=session_id).first()
    if not session_row:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    if user.role != "admin" and session_row.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return to_session_info(session_row)


@router.delete("/{session_id}", response_model=SessionInfo)
async def destroy_session(
    session_id: str,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user)
):
    """Destroy sandbox namespace, teardown pods, and trigger archival."""
    session_row = db.query(SessionModel).filter_by(id=session_id).first()
    if not session_row:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    if user.role != "admin" and session_row.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    # 1. Delete Kubernetes Namespace
    k8s_client.delete_sandbox(session_id)

    # 2. Update PostgreSQL record
    now = datetime.now(timezone.utc)
    session_row.status = "destroyed"
    session_row.destroyed_at = now
    db.commit()
    db.refresh(session_row)

    # 3. Audit teardown event
    teardown_event = NormalizedEvent(
        tenant_id=session_row.tenant_id,
        session_id=session_id,
        build_id=session_row.build_id,
        timestamp=now,
        source_type=SourceType.SOC_ACTION,
        source_name="orchestrator",
        actor=user.username,
        action=f"Destroyed sandbox session '{session_id}' and scheduled artifact archival",
        severity=Severity.LOW,
        outcome=Outcome.SUCCEEDED,
        provenance=getattr(session_row, "execution_mode", "simulated")
    )
    await event_sink.index_event(teardown_event)

    return to_session_info(session_row)


@router.post("/scan-dockerfile")
async def scan_dockerfile(payload: Dict[str, str]):
    """Static linter for a Dockerfile before launch using Hadolint."""
    content = payload.get("dockerfile", "")
    return SafetyScanner.lint_dockerfile(content)


@router.post("/scan-image")
async def scan_image(payload: Dict[str, str]):
    """CVE vulnerability check for a container image reference using Trivy."""
    img = payload.get("image", "target:latest")
    return SafetyScanner.scan_image(img)
