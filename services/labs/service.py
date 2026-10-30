"""
Labs Management Service
Enables multi-team, concurrent lab environments created from uploaded Dockerfiles,
docker-compose files, and archive build-contexts (.zip, .tar.gz).
Handles file validation, safety gate scanning, safe context extraction, and spawning
ephemeral sandbox sessions from verified Lab definitions.
"""
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Optional
import uuid
import yaml

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.db import get_db, Lab, SessionModel, Tenant
from shared.auth import get_current_user, require_roles, UserContext
from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from services.ingestion.opensearch_sink import event_sink
from services.orchestrator.scanner import SafetyScanner
from services.orchestrator.service import CreateSessionRequest, create_session, SessionInfo, to_session_info
from .builder import (
    SafeArchiveExtractor,
    ContextValidator,
    IsolatedContainerBuilder,
    BuildContextError,
    BUILD_CONTEXTS_ROOT
)

logger = logging.getLogger("cyberrange.labs")

router = APIRouter(prefix="/api/v1/labs", tags=["Lab Management & Multi-Environment"])

MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB limit


# --- Data Models ---

class LabDetailResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    dockerfile_content: Optional[str] = None
    compose_content: Optional[str] = None
    content_hash: Optional[str] = None
    build_id: Optional[str] = None
    image_tag: Optional[str] = None
    image_digest: Optional[str] = None
    uploaded_by: Optional[str] = None
    status: str  # uploaded, policy_checked, building, built, image_built, failed, build_failed, scan_inconclusive, ready, archived, demo
    build_status: Optional[str] = "pending"  # pending, building, built, failed, unavailable
    build_logs: Optional[str] = None
    safety_scan_result: Dict[str, Any] = Field(default_factory=dict)
    vulnerability_scan_result: Dict[str, Any] = Field(default_factory=dict)
    ports: List[Any] = Field(default_factory=list)
    is_demo: bool = False
    can_launch_live: bool = False
    created_at: datetime
    active_session_count: int = 0
    active_sessions: List[SessionInfo] = Field(default_factory=list)


class LaunchLabSessionRequest(BaseModel):
    ttl_minutes: int = Field(default=30, ge=5, le=240)
    build_id: Optional[str] = None
    skip_safety_gate: bool = False


def to_lab_response(lab: Lab, db: Session) -> LabDetailResponse:
    # Query active sessions running against this lab
    sessions = db.query(SessionModel).filter(
        SessionModel.lab_id == lab.id,
        SessionModel.status == "active"
    ).all()

    can_launch = bool(lab.image_digest and lab.status in ("ready", "built", "image_built"))

    return LabDetailResponse(
        id=lab.id,
        tenant_id=lab.tenant_id,
        name=lab.name,
        description=lab.description,
        dockerfile_content=lab.dockerfile_content,
        compose_content=lab.compose_content,
        content_hash=getattr(lab, "content_hash", None),
        build_id=getattr(lab, "build_id", None),
        image_tag=lab.image_tag,
        image_digest=getattr(lab, "image_digest", None),
        uploaded_by=lab.uploaded_by,
        status=lab.status,
        build_status=getattr(lab, "build_status", "pending"),
        build_logs=getattr(lab, "build_logs", None),
        safety_scan_result=lab.safety_scan_result or {},
        vulnerability_scan_result=getattr(lab, "vulnerability_scan_result", {}) or {},
        ports=getattr(lab, "ports", []) or [],
        is_demo=bool(getattr(lab, "is_demo", 0)),
        can_launch_live=can_launch,
        created_at=lab.created_at,
        active_session_count=len(sessions),
        active_sessions=[to_session_info(s) for s in sessions]
    )


# --- Endpoints ---

@router.post("", response_model=LabDetailResponse)
async def upload_lab(
    file: UploadFile = File(...),
    name: str = Form(...),
    description: Optional[str] = Form(None),
    tenant_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_roles(["admin"]))
):
    """
    Accepts multipart/form-data upload of a Dockerfile, docker-compose.yml, or
    archive bundle (.zip, .tar, .tar.gz) containing the build context.
    Validates static safety policies without falsely marking the image as built.
    """
    requested_tenant = tenant_id or user.tenant_id
    eff_tenant = requested_tenant
    if not name or not name.strip():
        raise HTTPException(status_code=400, detail="Lab name cannot be empty")

    # 1. Read and validate file size
    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024*1024)}MB"
        )
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    lab_id = f"lab-{uuid.uuid4().hex[:8]}"

    filename = (file.filename or "").lower()
    is_archive = filename.endswith((".zip", ".tar", ".tar.gz", ".tgz"))
    is_compose = not is_archive and ("compose" in filename or filename.endswith((".yaml", ".yml")))
    is_dockerfile = not is_archive and not is_compose and ("dockerfile" in filename or filename in {"", "upload"})

    if not is_archive and not is_dockerfile and not is_compose:
        raise HTTPException(status_code=400, detail="Upload a Dockerfile, docker-compose YAML, or project archive (.zip/.tar.gz)")

    dockerfile_content = None
    compose_content = None
    context_extracted_dir = None
    detected_ports: List[int] = []

    # 2. Extract and inspect content
    if is_archive:
        archive_dir = os.path.join(BUILD_CONTEXTS_ROOT, lab_id)
        try:
            if filename.endswith(".zip"):
                SafeArchiveExtractor.extract_zip(raw_bytes, archive_dir)
            else:
                SafeArchiveExtractor.extract_tar(raw_bytes, archive_dir)
            context_extracted_dir = archive_dir
        except BuildContextError as bce:
            raise HTTPException(status_code=400, detail=f"Invalid build archive: {bce}")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to extract build archive: {exc}")

        # Search for Dockerfile or compose file in extracted directory
        df_path = None
        for root, _, files in os.walk(archive_dir):
            for f in files:
                if f.lower() == "dockerfile":
                    df_path = os.path.join(root, f)
                    break
            if df_path:
                break

        comp_path = None
        if not df_path:
            for root, _, files in os.walk(archive_dir):
                for f in files:
                    if f.lower() in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                        comp_path = os.path.join(root, f)
                        break
                if comp_path:
                    break

        if not df_path and not comp_path:
            raise HTTPException(status_code=400, detail="Archive must contain a Dockerfile or docker-compose.yml")

        if df_path:
            is_dockerfile = True
            with open(df_path, "r", encoding="utf-8", errors="replace") as f:
                dockerfile_content = f.read()
        else:
            is_compose = True
            with open(comp_path, "r", encoding="utf-8", errors="replace") as f:
                compose_content = f.read()

    elif is_dockerfile:
        try:
            dockerfile_content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Uploaded Dockerfile must be UTF-8 encoded text")
        if "FROM " not in dockerfile_content.upper():
            raise HTTPException(status_code=400, detail="Invalid Dockerfile: Missing required 'FROM' instruction")

    elif is_compose:
        try:
            compose_content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Uploaded Compose file must be UTF-8 encoded text")
        try:
            compose_doc = yaml.safe_load(compose_content)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid Compose YAML: {exc}") from exc
        if not isinstance(compose_doc, dict) or not isinstance(compose_doc.get("services"), dict):
            raise HTTPException(status_code=400, detail="Compose file must contain a services mapping")

    # 3. Static policy checks
    safety_scan = {}
    if is_dockerfile and dockerfile_content:
        safety_scan = SafetyScanner.lint_dockerfile(dockerfile_content)
        detected_ports = ContextValidator.parse_dockerfile_ports(dockerfile_content)

        # Check if local files needed by COPY/ADD are missing
        has_context, missing_copies = ContextValidator.check_dockerfile_copy_targets(
            dockerfile_content, context_extracted_dir
        )
        if not has_context:
            safety_scan["missing_build_context_files"] = missing_copies
            safety_scan["context_warning"] = "Dockerfile contains COPY/ADD instructions but required local files were not provided."
    elif is_compose and compose_content:
        safety_scan = SafetyScanner.lint_compose(compose_content)

    scan_passed = safety_scan.get("passed", True)
    candidate_image_tag = f"lab-image:{content_hash[:12]}"
    safety_scan["candidate_image_tag"] = candidate_image_tag
    safety_scan["build_status"] = "pending" if scan_passed else "failed"

    # Status: static screening gives policy_checked when passed, or failed when blocked
    lab_status = "policy_checked" if scan_passed else "failed"
    build_status = "pending" if scan_passed else "failed"

    # 4. Persist Lab in Database
    new_lab = Lab(
        id=lab_id,
        tenant_id=eff_tenant,
        name=name.strip(),
        description=description.strip() if description else None,
        dockerfile_content=dockerfile_content,
        compose_content=compose_content,
        content_hash=content_hash,
        build_id=None,
        image_tag=None,  # Not marked built until an actual build occurs
        image_digest=None,
        uploaded_by=user.user_id,
        status=lab_status,
        build_status=build_status,
        build_logs=None,
        safety_scan_result=safety_scan,
        vulnerability_scan_result={},
        ports=detected_ports,
        is_demo=0,
        state_history=[{
            "from": "uploaded",
            "to": lab_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": user.username,
            "note": "Static policy check completed"
        }],
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_lab)
    db.commit()
    db.refresh(new_lab)

    # 5. Audit Event
    audit = NormalizedEvent(
        tenant_id=eff_tenant,
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.SOC_ACTION,
        source_name="labs_manager",
        actor=user.username,
        action=f"Admin uploaded Lab '{new_lab.name}' (id: {lab_id}, status: {lab_status})",
        severity=Severity.LOW if lab_status == "policy_checked" else Severity.HIGH,
        outcome=Outcome.SUCCEEDED if lab_status == "policy_checked" else Outcome.BLOCKED,
        provenance="live",
        raw_payload={
            "lab_id": lab_id,
            "filename": file.filename,
            "content_hash": content_hash,
            "scan_passed": scan_passed,
            "status": lab_status,
            "scan_mode": safety_scan.get("mode", "unknown")
        }
    )
    await event_sink.index_event(audit)

    return to_lab_response(new_lab, db)


@router.post("/{lab_id}/build", response_model=LabDetailResponse)
async def build_lab(
    lab_id: str,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_roles(["admin"]))
):
    """
    Builds a real container image from the uploaded lab's Dockerfile and context.
    Records the immutable digest and triggers a vulnerability scan.
    """
    lab = db.query(Lab).filter(Lab.id == lab_id).first()
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    if lab.status == "archived":
        raise HTTPException(status_code=400, detail="Cannot build an archived lab")
    if lab.status == "failed":
        raise HTTPException(status_code=400, detail="Cannot build a lab that failed static policy check")

    build_id = f"bld-{uuid.uuid4().hex[:8]}"
    lab.build_id = build_id
    lab.status = "building"
    lab.build_status = "building"
    db.commit()

    context_dir = os.path.join(BUILD_CONTEXTS_ROOT, lab.id)
    if not os.path.exists(context_dir):
        context_dir = None

    # Execute build via isolated container builder
    build_res = IsolatedContainerBuilder.build_image(
        lab_id=lab.id,
        build_id=build_id,
        dockerfile_content=lab.dockerfile_content or "",
        context_dir=context_dir
    )

    history_entry = {
        "from": "policy_checked",
        "to": build_res.get("status", "build_failed"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": user.username,
        "build_id": build_id,
        "builder": build_res.get("builder", "unknown")
    }

    if build_res["success"]:
        lab.status = "image_built"
        lab.build_status = "built"
        lab.image_tag = build_res["image_tag"]
        lab.image_digest = build_res["image_digest"]
        lab.build_logs = build_res["logs"]

        # Phase 2: Vulnerability Scan on exact image digest
        scan_res = SafetyScanner.scan_image(lab.image_digest)
        lab.vulnerability_scan_result = scan_res
        if scan_res.get("status") == "scan_complete":
            lab.status = "ready"
        elif scan_res.get("status") in ("scan_inconclusive", "scan_failed"):
            lab.status = scan_res.get("status")
    else:
        lab.status = "build_failed"
        lab.build_status = build_res.get("status", "failed")
        lab.build_logs = build_res.get("logs", "") or build_res.get("error", "")

    history = lab.state_history or []
    history.append(history_entry)
    lab.state_history = history
    db.commit()
    db.refresh(lab)

    audit = NormalizedEvent(
        tenant_id=lab.tenant_id,
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.SOC_ACTION,
        source_name="labs_builder",
        actor=user.username,
        action=f"Lab '{lab.name}' build outcome: {lab.status} (build_id: {build_id})",
        severity=Severity.LOW if lab.build_status == "built" else Severity.HIGH,
        outcome=Outcome.SUCCEEDED if lab.build_status == "built" else Outcome.FAILED,
        provenance="live",
        raw_payload={
            "lab_id": lab.id,
            "build_id": build_id,
            "image_tag": lab.image_tag,
            "image_digest": lab.image_digest,
            "status": lab.status
        }
    )
    await event_sink.index_event(audit)

    return to_lab_response(lab, db)


@router.get("", response_model=List[LabDetailResponse])
async def list_labs(
    tenant_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user)
):
    """
    Lists all real registered Labs available across teams, excluding archived ones.
    Does not insert synthetic or demo labs implicitly into ordinary lab listings.
    """
    query = db.query(Lab).filter(Lab.status != "archived")
    if user.role != "admin":
        query = query.filter((Lab.tenant_id == user.tenant_id) | (Lab.is_demo == 1))
    labs = query.order_by(Lab.created_at.desc()).all()
    return [to_lab_response(l, db) for l in labs]


@router.get("/{lab_id}", response_model=LabDetailResponse)
async def get_lab(
    lab_id: str, db: Session = Depends(get_db), user: UserContext = Depends(get_current_user)
):
    """Retrieve a lab definition by ID."""
    lab = db.query(Lab).filter(Lab.id == lab_id, Lab.status != "archived").first()
    if not lab:
        raise HTTPException(status_code=404, detail=f"Lab '{lab_id}' not found")
    if user.role != "admin" and lab.tenant_id != user.tenant_id and not lab.is_demo:
        raise HTTPException(status_code=404, detail=f"Lab '{lab_id}' not found")
    return to_lab_response(lab, db)


@router.post("/{lab_id}/sessions", response_model=SessionInfo)
async def launch_session_from_lab(
    lab_id: str,
    req: LaunchLabSessionRequest,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user)
):
    """
    Launches a new isolated sandbox session from a verified built Lab.
    Fails closed if the lab has not been built into an immutable image artifact.
    """
    lab = db.query(Lab).filter(Lab.id == lab_id, Lab.status != "archived").first()
    if not lab:
        raise HTTPException(status_code=404, detail=f"Lab '{lab_id}' not found")
    if user.role != "admin" and lab.tenant_id != user.tenant_id and not lab.is_demo:
        raise HTTPException(status_code=404, detail=f"Lab '{lab_id}' not found")

    if lab.status == "archived":
        raise HTTPException(status_code=400, detail="Cannot launch sessions against an archived Lab")
    if lab.status in ("failed", "policy_blocked"):
        raise HTTPException(status_code=400, detail="Cannot launch sessions against a Lab that failed security policy checks")

    # Critical requirement: An unbuilt lab cannot launch
    if lab.status in ("policy_checked", "uploaded", "validating", "building", "build_failed", "pending") or not lab.image_tag:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"Cannot launch session: Lab '{lab.name}' (status: '{lab.status}') has not been built into a container image artifact.",
                "lab_id": lab.id,
                "status": lab.status,
                "next_step": f"Trigger POST /api/v1/labs/{lab.id}/build to build the image before launching a session."
            }
        )

    if req.skip_safety_gate and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only an admin may request a safety-gate override")

    # Use the verified built image artifact
    target_image = lab.image_digest or lab.image_tag

    session_req = CreateSessionRequest(
        tenant_id=user.tenant_id,
        lab_id=lab.id,
        target_image=target_image,
        build_id=req.build_id or lab.build_id,
        ttl_minutes=req.ttl_minutes,
        dockerfile_content=lab.dockerfile_content,
        skip_safety_gate=req.skip_safety_gate
    )

    session_info = await create_session(session_req, db=db, user=user)
    return session_info


@router.delete("/{lab_id}")
async def archive_lab(
    lab_id: str,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_roles(["admin"]))
):
    """Archives a Lab so no new sessions can be launched. Administrator only."""
    lab = db.query(Lab).filter_by(id=lab_id).first()
    if not lab:
        raise HTTPException(status_code=404, detail=f"Lab '{lab_id}' not found")

    lab.status = "archived"
    db.commit()

    return {"status": "archived", "lab_id": lab_id, "name": lab.name}
