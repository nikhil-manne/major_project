"""
Labs Management Service
Enables multi-team, concurrent lab environments created from uploaded Dockerfiles and docker-compose files.
Handles file validation, safety gate scanning, and spawning ephemeral sandbox sessions from persistent Lab definitions.
"""
from datetime import datetime, timezone
import hashlib
import logging
from typing import Any, Dict, List, Optional
import yaml
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.db import get_db, Lab, SessionModel, Tenant
from shared.auth import get_current_user, require_roles, UserContext
from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from services.ingestion.opensearch_sink import event_sink
from services.orchestrator.scanner import SafetyScanner
from services.orchestrator.service import CreateSessionRequest, create_session, SessionInfo, to_session_info

logger = logging.getLogger("cyberrange.labs")

router = APIRouter(prefix="/api/v1/labs", tags=["Lab Management & Multi-Environment"])

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit


# --- Data Models ---

class LabDetailResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    dockerfile_content: Optional[str] = None
    compose_content: Optional[str] = None
    image_tag: Optional[str] = None
    uploaded_by: Optional[str] = None
    status: str  # uploaded, policy_checked, built, failed, archived, reference
    safety_scan_result: Dict[str, Any] = Field(default_factory=dict)
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

    return LabDetailResponse(
        id=lab.id,
        tenant_id=lab.tenant_id,
        name=lab.name,
        description=lab.description,
        dockerfile_content=lab.dockerfile_content,
        compose_content=lab.compose_content,
        image_tag=lab.image_tag,
        uploaded_by=lab.uploaded_by,
        status=lab.status,
        safety_scan_result=lab.safety_scan_result or {},
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
    Accepts multipart/form-data upload of a Dockerfile or docker-compose.yml.
    Only Administrators can register new lab environments or upload Dockerfiles.
    Registers the lab as a common environment ready for teams to launch sandboxes.
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

    try:
        content_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must be UTF-8 encoded text"
        )

    filename = (file.filename or "").lower()
    is_compose = "compose" in filename or filename.endswith((".yaml", ".yml"))
    is_dockerfile = not is_compose and ("dockerfile" in filename or filename in {"", "upload"})
    if not is_dockerfile and not is_compose:
        raise HTTPException(status_code=400, detail="Upload a Dockerfile or docker-compose YAML file")

    # 2. Content plausibility check
    if is_dockerfile:
        if "FROM " not in content_text.upper():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Dockerfile: Missing required 'FROM' instruction"
            )
    elif is_compose:
        try:
            compose_doc = yaml.safe_load(content_text)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid Compose YAML: {exc}") from exc
        if not isinstance(compose_doc, dict) or not isinstance(compose_doc.get("services"), dict):
            raise HTTPException(status_code=400, detail="Compose file must contain a services mapping")

    # 3. Compute Content Hash to derive candidate image tag
    file_hash = hashlib.sha256(raw_bytes).hexdigest()[:12]
    lab_id = f"lab-{uuid.uuid4().hex[:8]}"

    candidate_image_tag = f"lab-image:{file_hash}"
    if is_dockerfile:
        for line in content_text.splitlines():
            line_s = line.strip()
            if line_s.upper().startswith("FROM "):
                parts = line_s.split()
                if len(parts) > 1:
                    base_ref = parts[1]
                    safe_ref = base_ref.replace("/", "-").replace(":", "-").replace("@", "-")
                    candidate_image_tag = f"lab-{safe_ref}:{file_hash}"
                break

    # Static policy validation
    if is_dockerfile:
        safety_scan = SafetyScanner.lint_dockerfile(content_text)
    else:
        safety_scan = SafetyScanner.lint_compose(content_text)
    safety_scan["candidate_image_tag"] = candidate_image_tag
    scan_passed = safety_scan.get("passed", True)
    safety_scan["build_status"] = "built" if scan_passed else "failed"
    lab_status = "built" if scan_passed else "failed"

    # 5. Persist Lab in Database as a common environment ready for teams
    new_lab = Lab(
        id=lab_id,
        tenant_id=eff_tenant,
        name=name.strip(),
        description=description.strip() if description else None,
        dockerfile_content=content_text if is_dockerfile else None,
        compose_content=content_text if is_compose else None,
        image_tag=candidate_image_tag,
        uploaded_by=user.user_id,
        status=lab_status,
        safety_scan_result=safety_scan,
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_lab)
    db.commit()
    db.refresh(new_lab)

    # 6. Audit Event
    audit = NormalizedEvent(
        tenant_id=eff_tenant,
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.SOC_ACTION,
        source_name="labs_manager",
        actor=user.username,
        action=f"Admin registered Common Lab '{new_lab.name}' (id: {lab_id}, status: {lab_status})",
        severity=Severity.LOW if lab_status == "built" else Severity.HIGH,
        outcome=Outcome.SUCCEEDED if lab_status == "built" else Outcome.BLOCKED,
        raw_payload={
            "lab_id": lab_id,
            "filename": file.filename,
            "hash": file_hash,
            "scan_passed": scan_passed,
            "scan_mode": safety_scan.get("mode", "unknown"),
            "image_tag": candidate_image_tag
        }
    )
    await event_sink.index_event(audit)

    return to_lab_response(new_lab, db)


@router.get("", response_model=List[LabDetailResponse])
async def list_labs(
    tenant_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: UserContext = Depends(get_current_user)
):
    """
    Lists all reusable Common Labs available across teams, excluding archived ones.
    Every user can see and switch between these common labs.
    """
    query = db.query(Lab).filter(Lab.status != "archived")
    labs = query.order_by(Lab.created_at.desc()).all()

    # Seed baseline labs if none exist yet for instant out-of-the-box experience
    if not labs:
        demo_dockerfile = (
            "FROM vulhub/struts2-core:2.3.31\n"
            "EXPOSE 8080\n"
            "USER www-data\n"
            "CMD [\"catalina.sh\", \"run\"]\n"
        )
        scan = SafetyScanner.lint_dockerfile(demo_dockerfile)
        default_lab = Lab(
            id="lab-demo-struts",
            tenant_id=user.tenant_id or "00000000-0000-0000-0000-000000000123",
            name="Vulnerable Apache Struts E-Commerce",
            description="Standing multi-team challenge lab vulnerable to CVE-2017-5638 RCE and T1210 lateral movement.",
            dockerfile_content=demo_dockerfile,
            image_tag="vulhub/struts2-core:2.3.31",
            uploaded_by="usr-admin-4444",
            status="built",
            safety_scan_result={**scan, "mode": "policy_passed", "verified": True, "build_status": "built"},
            created_at=datetime.now(timezone.utc)
        )
        db.add(default_lab)
        db.commit()
        db.refresh(default_lab)
        labs = [default_lab]

    return [to_lab_response(l, db) for l in labs]


@router.get("/{lab_id}", response_model=LabDetailResponse)
async def get_lab(
    lab_id: str, db: Session = Depends(get_db), user: UserContext = Depends(get_current_user)
):
    """Retrieve a common lab definition by ID."""
    lab = db.query(Lab).filter(Lab.id == lab_id, Lab.status != "archived").first()
    if not lab:
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
    Launches a new isolated sandbox session from this common Lab definition.
    Any authenticated user (red, blue, soc, admin) can spawn multiple sandboxes
    of the same existing lab as needed.
    """
    lab = db.query(Lab).filter(Lab.id == lab_id, Lab.status != "archived").first()
    if not lab:
        raise HTTPException(status_code=404, detail=f"Lab '{lab_id}' not found")

    if lab.status == "archived":
        raise HTTPException(status_code=400, detail="Cannot launch sessions against an archived Lab")
    if lab.status == "failed":
        raise HTTPException(status_code=400, detail="Cannot launch sessions against a Lab that failed security policy checks")
    if req.skip_safety_gate and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only an admin may request a safety-gate override")

    target_image = lab.image_tag or "vulhub/struts2-core:2.3.31"

    session_req = CreateSessionRequest(
        tenant_id=user.tenant_id,
        lab_id=lab.id,
        target_image=target_image,
        build_id=req.build_id,
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
