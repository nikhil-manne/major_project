"""
Attack Engine API
Exposes Red Team scenario execution, live interactive terminal commands,
and asciinema recording streams backed by real Kubernetes toolbox pods and MinIO storage.
"""
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.auth import get_current_user, require_roles, UserContext
from shared.kafka_client import kafka_producer
from shared.config import settings
from shared.s3_client import s3_client
from shared.db import db_context, SessionModel
from services.ingestion.opensearch_sink import event_sink
from services.orchestrator.k8s_client import k8s_client
from .runner import AttackScenarioRunner

logger = logging.getLogger("cyberrange.attack")

router = APIRouter(prefix="/api/v1/attack", tags=["Red Team Attack Engine"])

# In-memory terminal transcript cache. Each cast has explicit provenance so simulated
# scenario output is never advertised as a real terminal recording.
session_casts: Dict[str, List[Any]] = {}
session_cast_modes: Dict[str, str] = {}


def _merge_cast_mode(session_id: str, mode: str) -> None:
    current = session_cast_modes.get(session_id)
    if current is None:
        session_cast_modes[session_id] = mode
    elif current != mode:
        session_cast_modes[session_id] = "mixed"


class ExecuteScenarioRequest(BaseModel):
    scenario_id: str
    session_id: str
    tenant_id: Optional[str] = None
    build_id: Optional[str] = None
    operator: str = "red1"


class InteractiveCommandRequest(BaseModel):
    session_id: str
    command: str
    tenant_id: Optional[str] = None
    operator: str = "red1"
    mitre_technique: Optional[str] = None


def _authorize_active_session(session_id: str, user: UserContext) -> SessionModel:
    """Require an existing active session in the caller's tenant before any test command."""
    with db_context() as db:
        query = db.query(SessionModel).filter_by(id=session_id, tenant_id=user.tenant_id)
        session_row = query.first()
        if not session_row and user.role == "admin":
            session_row = db.query(SessionModel).filter_by(id=session_id).first()
        if not session_row:
            raise HTTPException(status_code=404, detail="Session not found in the authorized tenant")
        if session_row.status != "active":
            raise HTTPException(status_code=409, detail=f"Session is not active (status={session_row.status})")
        # Return a detached copy of the small fields used by the route.
        return SessionModel(
            id=session_row.id, tenant_id=session_row.tenant_id, lab_id=session_row.lab_id,
            build_id=session_row.build_id, target_image=session_row.target_image,
            namespace=session_row.namespace, status=session_row.status,
            created_at=session_row.created_at, expires_at=session_row.expires_at,
            isolation=session_row.isolation, safety_scan=session_row.safety_scan
        )


@router.get("/scenarios")
async def list_scenarios():
    """List all registered MITRE ATT&CK adversary emulation playbooks."""
    return AttackScenarioRunner.load_available_scenarios()


@router.post("/execute")
async def execute_scenario(
    req: ExecuteScenarioRequest,
    user: UserContext = Depends(require_roles(["red", "admin"]))
):
    """Launch an automated attack scenario against a sandbox session."""
    try:
        if req.tenant_id and req.tenant_id != user.tenant_id and user.role != "admin":
            raise HTTPException(status_code=403, detail="You cannot execute a scenario for another tenant")
        session_row = _authorize_active_session(req.session_id, user)
        eff_tenant = session_row.tenant_id
        eff_operator = user.username or req.operator

        result = await AttackScenarioRunner.execute_scenario(
            scenario_id=req.scenario_id,
            session_id=req.session_id,
            tenant_id=eff_tenant,
            build_id=req.build_id,
            operator=eff_operator
        )
        session_casts[req.session_id] = result["terminal_cast"]
        _merge_cast_mode(req.session_id, result.get("execution_mode", "simulated"))

        # Also store to S3 if available
        s3_client.upload_json(
            result["terminal_cast"],
            f"/sessions/{req.session_id}/terminal.cast"
        )

        return {
            "status": "completed",
            "scenario": result["name"],
            "technique": result["technique"],
            "steps_executed": result["steps_executed"],
            "execution_mode": result["execution_mode"],
            "live_steps": result["live_steps"],
            "simulated_steps": result["simulated_steps"],
            "blocked_steps": result["blocked_steps"],
            "session_id": req.session_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Scenario execution failed")
        raise HTTPException(status_code=400, detail="Scenario execution failed; consult server logs for details") from e


@router.post("/terminal/execute-command")
async def execute_terminal_command(
    req: InteractiveCommandRequest,
    user: UserContext = Depends(require_roles(["red", "admin"]))
):
    """
    Executes a manual Red Team command in the real Kubernetes toolbox pod,
    captures real stdout, publishes event to Kafka, and appends to asciinema cast.
    """
    cmd = req.command.strip()
    if req.tenant_id and req.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You cannot execute a command for another tenant")
    session_row = _authorize_active_session(req.session_id, user)
    eff_tenant = session_row.tenant_id
    eff_operator = user.username or req.operator

    # Commands are executed only through the toolbox client's allowlist. In simulation
    # mode the response explicitly says no command ran; no canned exploit success is emitted.
    real_exec = k8s_client.exec_command_in_toolbox(req.session_id, cmd)
    output = real_exec.get("output", "")

    inferred_technique = req.mitre_technique or "T1059"
    inferred_tactic = "TA0002"
    cmd_lower = cmd.lower()
    if cmd_lower.startswith("nmap"):
        inferred_technique, inferred_tactic = "T1046", "TA0007"
    elif "msf" in cmd_lower or "exploit" in cmd_lower or "smb" in cmd_lower:
        inferred_technique, inferred_tactic = "T1210", "TA0008"
    elif "sqlmap" in cmd_lower or "select" in cmd_lower or "curl" in cmd_lower or "http" in cmd_lower or "t1190" in cmd_lower or "api/" in cmd_lower:
        inferred_technique, inferred_tactic = "T1190", "TA0001"

    execution_mode = real_exec.get("execution_mode", "simulated")
    if execution_mode == "simulated":
        outcome = Outcome.SIMULATED
    elif execution_mode == "blocked":
        outcome = Outcome.BLOCKED
    elif execution_mode == "failed":
        outcome = Outcome.INCONCLUSIVE
    else:
        # Output was returned, but the stream wrapper does not establish exploit success.
        outcome = Outcome.INCONCLUSIVE

    # 2. Emit normalized event
    event = NormalizedEvent(
        tenant_id=eff_tenant,
        session_id=req.session_id,
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.ATTACK,
        source_name="web_terminal",
        actor=eff_operator,
        action=cmd,
        mitre_tactic=inferred_tactic,
        mitre_technique=inferred_technique,
        severity=Severity.HIGH,
        outcome=outcome,
        raw_payload={
            "terminal_output": output,
            "cwd": "/workspace",
            "executed_live": real_exec.get("executed_live", False),
            "execution_mode": execution_mode,
            "outcome_note": "Command execution is not proof that the intended attack succeeded."
        }
    )

    # Publish to Kafka raw.attack topic
    kafka_producer.produce(
        topic=settings.TOPIC_RAW_ATTACK,
        key=req.session_id,
        value=event.model_dump()
    )

    await event_sink.index_event(event)

    # 3. Append to asciinema cast
    if req.session_id not in session_casts:
        session_casts[req.session_id] = [
            {"version": 2, "width": 120, "height": 36, "timestamp": int(datetime.now(timezone.utc).timestamp())}
        ]
    session_casts[req.session_id].append([1.0, "o", f"\r\n\x1b[31;1mredteam@toolbox\x1b[0m:~$ {cmd}\r\n{output}\r\n"])
    _merge_cast_mode(req.session_id, execution_mode if real_exec.get("executed_live") else "simulated")

    return {
        "command": cmd,
        "output": output,
        "mitre_technique": inferred_technique,
        "event_id": event.event_id,
        "live_executed": real_exec.get("executed_live", False),
        "execution_mode": execution_mode,
        "outcome": outcome.value
    }


@router.get("/casts/{session_id}")
async def get_session_cast(session_id: str, user: UserContext = Depends(get_current_user)):
    """Retrieve full asciinema terminal recording for an authorized session."""
    _authorize_active_session(session_id, user)
    # Check memory first
    cast = session_casts.get(session_id)
    if not cast:
        # Try reading from S3/MinIO
        s3_cast = s3_client.get_json(f"/sessions/{session_id}/terminal.cast")
        if s3_cast:
            return s3_cast

        # Return baseline cast
        return [
            {"version": 2, "width": 120, "height": 36, "timestamp": int(datetime.now(timezone.utc).timestamp())},
            [0.5, "o", "No terminal sessions recorded for this session yet.\r\n"]
        ]
    return cast


@router.get("/terminal/ttyd-info/{session_id}")
async def get_ttyd_terminal_info(session_id: str, user: UserContext = Depends(require_roles(["red", "admin"]))) -> Dict[str, Any]:
    """Return terminal proxy metadata only for an authorized active session."""
    _authorize_active_session(session_id, user)
    if not k8s_client.is_connected:
        raise HTTPException(status_code=503, detail="Live terminal is unavailable without a connected Kubernetes cluster")
    return {
        "session_id": session_id,
        "namespace": f"sandbox-{session_id}",
        "pod_name": "redteam-toolbox",
        "ttyd_port": 7681,
        "protocol": "ws",
        "path": f"/k8s/namespaces/sandbox-{session_id}/pods/redteam-toolbox:7681/proxy/"
    }
