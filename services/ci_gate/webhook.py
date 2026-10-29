"""
CI/CD Pre-Release Security Gate Webhook
Provides automated security testing pipeline triggered by CI/CD workflows,
persisting build gate metrics to PostgreSQL.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.db import get_db, BuildModel, db_context
from shared.auth import get_current_user, require_roles, UserContext
from services.orchestrator.service import CreateSessionRequest, create_session, destroy_session
from services.attack_engine.runner import AttackScenarioRunner
from services.detection_engine.service import EvaluateRequest, evaluate_detection_rules
from services.scoring_engine.service import calculate_readiness_score
from services.replay_engine.archiver import SessionArchiver
from services.ingestion.opensearch_sink import event_sink

logger = logging.getLogger("cyberrange.ci_gate")

router = APIRouter(prefix="/api/v1/ci-gate", tags=["Pre-Release CI/CD Security Gate"])


class BuildDBProxy(dict):
    """Backwards-compatible dict proxy backed by PostgreSQL builds table."""
    def get(self, key: str, default=None):
        try:
            with db_context() as db:
                b = db.query(BuildModel).filter_by(id=key).first()
                if b:
                    return {
                        "build_id": b.id,
                        "commit_hash": b.commit_hash,
                        "repository": b.repository,
                        "branch": b.branch,
                        "image_tag": b.image_tag,
                        "session_id": b.session_id,
                        "gate_result": b.gate_result.upper(),
                        "readiness_score": b.readiness_score,
                        "coverage_percentage": b.coverage_percentage,
                        "gap_count": b.gap_count,
                        "created_at": b.created_at.isoformat() if b.created_at else "",
                        "report_markdown": b.report_markdown,
                        "score_details": b.score_details or {}
                    }
                return default
        except Exception:
            return default

    def values(self):
        try:
            with db_context() as db:
                builds = db.query(BuildModel).all()
                return [
                    {
                        "build_id": b.id,
                        "commit_hash": b.commit_hash,
                        "repository": b.repository,
                        "branch": b.branch,
                        "image_tag": b.image_tag,
                        "session_id": b.session_id,
                        "gate_result": b.gate_result.upper(),
                        "readiness_score": b.readiness_score,
                        "coverage_percentage": b.coverage_percentage,
                        "gap_count": b.gap_count,
                        "created_at": b.created_at.isoformat() if b.created_at else "",
                        "report_markdown": b.report_markdown,
                        "score_details": b.score_details or {}
                    }
                    for b in builds
                ]
        except Exception:
            return []


builds_db = BuildDBProxy()


class CIWebhookPayload(BaseModel):
    repository: str = "acme/payment-service"
    commit_hash: str = Field(default_factory=lambda: uuid.uuid4().hex[:7])
    image_tag: str = "vulnerable-web:latest"
    branch: str = "main"
    tenant_id: Optional[str] = None
    min_score_threshold: float = Field(default=75.0, ge=0.0, le=100.0)
    dockerfile_content: Optional[str] = None


@router.post("/webhook")
async def trigger_ci_security_gate(
    payload: CIWebhookPayload,
    db: Session = Depends(get_db),
    user: UserContext = Depends(require_roles(["admin", "soc"]))
):
    """
    Automated pre-release security testing gate.
    Spins up sandbox -> runs scenarios -> detects -> computes readiness score -> passes/fails release.
    """
    if payload.tenant_id and payload.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot run a CI gate for another tenant")
    if payload.dockerfile_content:
        raise HTTPException(status_code=409, detail={
            "message": "This version evaluates an existing image reference; it does not build uploaded Dockerfiles.",
            "dockerfile_executed": False,
            "next_step": "Build the Dockerfile in an isolated image-builder service and submit the resulting immutable image digest."
        })
    eff_tenant = payload.tenant_id if (payload.tenant_id and user.role == "admin") else user.tenant_id
    build_id = f"bld-{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc)

    # 1. Spawn Ephemeral Sandbox Session
    session_req = CreateSessionRequest(
        tenant_id=eff_tenant,
        target_image=payload.image_tag,
        build_id=build_id,
        ttl_minutes=15,
        dockerfile_content=payload.dockerfile_content,
        skip_safety_gate=False
    )
    session = await create_session(session_req, db=db, user=user)
    session_id = session.session_id

    # 2. Automatically Run Scripted Attack Scenarios
    scenarios_to_run = ["scn-recon-01", "scn-smb-02", "scn-sh-03"]
    attack_results = []
    for scn_id in scenarios_to_run:
        try:
            res = await AttackScenarioRunner.execute_scenario(
                scenario_id=scn_id,
                session_id=session_id,
                tenant_id=eff_tenant,
                build_id=build_id,
                operator="ci_automated_red_runner"
            )
            attack_results.append(res)
        except Exception:
            pass

    # 3. Run Detection Evaluation
    eval_req = EvaluateRequest(session_id=session_id, tenant_id=eff_tenant)
    det_res = await evaluate_detection_rules(eval_req, user=user)

    # 4. Compute Coverage and Readiness Score
    score_report = await calculate_readiness_score(
        tenant_id=eff_tenant,
        session_id=session_id,
        build_id=build_id,
        db=db,
        user=user
    )

    # 5. Evaluate Gate Decision
    live_steps = sum(int(result.get("live_steps", 0)) for result in attack_results)
    tested_techniques = int(score_report.breakdown.get("tested_techniques", 0))
    live_mode = bool((session.isolation or {}).get("execution_mode") == "live")
    passed = live_mode and live_steps > 0 and tested_techniques > 0 and (score_report.score >= payload.min_score_threshold) and (score_report.breakdown.get("gap_count", 0) == 0)
    if not live_mode or live_steps == 0 or tested_techniques == 0:
        gate_decision = "INCONCLUSIVE"
    else:
        gate_decision = "PASS" if passed else "FAIL"

    # 6. Tear down sandbox and archive session
    await destroy_session(session_id, db=db, user=user)
    SessionArchiver.archive_session(session_id=session_id, tenant_id=eff_tenant)

    # 7. Build Markdown Report Summary
    report_markdown = f"""# Pre-Release Security Gate Report
- **Repository:** `{payload.repository}`
- **Commit:** `{payload.commit_hash}`
- **Build ID:** `{build_id}`
- **Gate Result:** **{gate_decision}**
- **Security Readiness Score:** **{score_report.score} / 100** (Threshold: {payload.min_score_threshold})
- **MITRE Coverage:** {score_report.coverage_pct}%
- **Techniques Covered:** {score_report.breakdown.get('covered_count', 0)}
- **Techniques with Gaps:** {score_report.breakdown.get('gap_count', 0)}
- **Avg Detection Latency:** {score_report.avg_detection_latency_sec}s
"""

    record = {
        "build_id": build_id,
        "commit_hash": payload.commit_hash,
        "repository": payload.repository,
        "branch": payload.branch,
        "image_tag": payload.image_tag,
        "session_id": session_id,
        "gate_result": gate_decision,
        "execution_mode": "live" if live_mode else "simulated",
        "live_steps": live_steps,
        "tested_techniques": tested_techniques,
        "readiness_score": score_report.score,
        "coverage_percentage": score_report.coverage_pct,
        "gap_count": score_report.breakdown.get("gap_count", 0),
        "created_at": start_time.isoformat(),
        "report_markdown": report_markdown,
        "score_details": score_report.model_dump(mode="json")
    }

    # Persist in PostgreSQL
    try:
        build_model = BuildModel(
            id=build_id,
            tenant_id=eff_tenant,
            commit_hash=payload.commit_hash,
            repository=payload.repository,
            branch=payload.branch,
            image_tag=payload.image_tag,
            session_id=session_id,
            readiness_score=score_report.score,
            gate_result=gate_decision.lower(),
            coverage_percentage=score_report.coverage_pct,
            gap_count=score_report.breakdown.get("gap_count", 0),
            report_markdown=report_markdown,
            score_details=score_report.model_dump(mode="json"),
            created_at=start_time
        )
        db.add(build_model)
        db.commit()
    except Exception as e:
        logger.warning(f"Failed to persist build to DB: {e}")

    return record


@router.get("/builds")
async def list_builds(db: Session = Depends(get_db), user: UserContext = Depends(get_current_user)):
    """List builds from the authenticated tenant."""
    try:
        builds = db.query(BuildModel).filter_by(tenant_id=user.tenant_id).order_by(BuildModel.created_at.desc()).all()
        return [
            {
                "build_id": b.id,
                "commit_hash": b.commit_hash,
                "repository": b.repository,
                "branch": b.branch,
                "image_tag": b.image_tag,
                "session_id": b.session_id,
                "gate_result": b.gate_result.upper(),
                "readiness_score": b.readiness_score,
                "coverage_percentage": b.coverage_percentage,
                "gap_count": b.gap_count,
                "created_at": b.created_at.isoformat() if b.created_at else "",
                "report_markdown": b.report_markdown,
                "score_details": b.score_details or {}
            }
            for b in builds
        ]
    except Exception:
        return []


@router.get("/builds/{build_id}")
async def get_build(build_id: str, db: Session = Depends(get_db), user: UserContext = Depends(get_current_user)):
    """Retrieve a build report only within the authenticated tenant."""
    b = db.query(BuildModel).filter_by(id=build_id, tenant_id=user.tenant_id).first()
    if not b and user.role == "admin":
        b = db.query(BuildModel).filter_by(id=build_id).first()
    if not b:
        raise HTTPException(status_code=404, detail=f"Build {build_id} not found")
    return {
        "build_id": b.id,
        "commit_hash": b.commit_hash,
        "repository": b.repository,
        "branch": b.branch,
        "image_tag": b.image_tag,
        "session_id": b.session_id,
        "gate_result": b.gate_result.upper(),
        "readiness_score": b.readiness_score,
        "coverage_percentage": b.coverage_percentage,
        "gap_count": b.gap_count,
        "created_at": b.created_at.isoformat() if b.created_at else "",
        "report_markdown": b.report_markdown,
        "score_details": b.score_details or {}
    }
