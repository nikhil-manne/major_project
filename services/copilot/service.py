"""
AI Security Copilot Service API
Provides role-tailored AI assistance: alert explanation, Sigma generation, attack suggestions, and summaries.
"""
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Depends
import httpx
from pydantic import BaseModel, Field

from shared.config import settings
from shared.schema import NormalizedEvent
from services.ingestion.opensearch_sink import event_sink
from services.detection_engine.sigma_compiler import SigmaEngine
from .prompts import SYSTEM_PROMPTS
from shared.auth import get_current_user, require_roles, UserContext
from shared.db import db_context, SessionModel

router = APIRouter(prefix="/api/v1/copilot", tags=["AI Security Copilot"])


def _effective_tenant(requested_tenant: Optional[str], user: UserContext) -> str:
    if requested_tenant and requested_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot access another tenant's Copilot context")
    return requested_tenant if (requested_tenant and user.role == "admin") else user.tenant_id


def _authorize_copilot_session(session_id: str, user: UserContext, requested_tenant: Optional[str] = None) -> str:
    effective_tenant = _effective_tenant(requested_tenant, user)
    with db_context() as db:
        row = db.query(SessionModel).filter_by(id=session_id, tenant_id=effective_tenant).first()
        if not row and user.role == "admin":
            row = db.query(SessionModel).filter_by(id=session_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found in the authorized tenant")
        if row.tenant_id != effective_tenant and user.role != "admin":
            raise HTTPException(status_code=403, detail="Session is outside the authorized tenant")
        return row.tenant_id


def _prompt_role_for_user(user: UserContext) -> str:
    # Administrative users receive SOC assistance by default rather than implicitly gaining Red Team guidance.
    return user.role if user.role in {"red", "blue", "soc"} else "soc"


class CopilotChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    # Supplied role is informational only; the authenticated role determines permissions.
    role: Optional[str] = Field(default=None, description="Ignored; derived from verified identity")
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    event_context_id: Optional[str] = None


class ExplainAlertRequest(BaseModel):
    event_id: str
    tenant_id: Optional[str] = None


class GenerateRuleRequest(BaseModel):
    technique_id: str = Field(..., min_length=3, max_length=32)
    gap_description: str = Field(..., min_length=1, max_length=4000)
    target_service: Optional[str] = Field(default="web/network", max_length=200)
    tenant_id: Optional[str] = None


class SuggestAttackRequest(BaseModel):
    recon_output: str = Field(..., min_length=1, max_length=10000)
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None


class SummarizeSessionRequest(BaseModel):
    session_id: str
    tenant_id: Optional[str] = None


class CopilotEngine:
    @staticmethod
    async def query_llm(system_prompt: str, user_prompt: str) -> tuple[str, str]:
        """Call the configured Anthropic API or use a clearly labelled deterministic demo fallback."""
        api_key = settings.ANTHROPIC_API_KEY
        if api_key and api_key != "dev_placeholder_or_local_mock" and not api_key.startswith("dev_"):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    res = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": api_key,
                            "anthropic-version": settings.ANTHROPIC_API_VERSION,
                            "content-type": "application/json"
                        },
                        json={
                            "model": settings.ANTHROPIC_MODEL,
                            "max_tokens": 1024,
                            "system": system_prompt,
                            "messages": [{"role": "user", "content": user_prompt}]
                        }
                    )
                    if res.status_code == 200:
                        data = res.json()
                        content = data.get("content", [])
                        text_blocks = [block.get("text", "") for block in content if block.get("type") == "text"]
                        if text_blocks:
                            return "\n".join(text_blocks), "anthropic_api"
                    logger.warning("Anthropic Copilot request failed (HTTP %s); using local demo fallback", res.status_code)
            except Exception as exc:
                logger.warning("Anthropic Copilot request failed; using local demo fallback: %s", exc)

        return CopilotEngine._local_security_reasoning(system_prompt, user_prompt), "local_deterministic_demo_fallback"

    @staticmethod
    def _local_security_reasoning(system_prompt: str, user_prompt: str) -> str:
        """
        Deterministic canned response for offline development; this is not an LLM or RAG system.
        """
        prompt_lower = user_prompt.lower()

        # This offline fallback must not invent a specific incident, technique, or sensor observation.
        if "explain alert" in prompt_lower or "explain this" in prompt_lower:
            return (
                "### Alert Review (Deterministic Demo Fallback)\n\n"
                "This offline fallback cannot independently verify the alert or infer that an exploit succeeded. "
                "Review the stored alert's rule ID, severity, triggering event ID, timestamp, and raw evidence. "
                "Confirm that the linked event belongs to the same tenant and session, then compare it with the "
                "detection rule's exact conditions. A rule match alone is not proof of compromise.\n\n"
                "Suggested analyst checks: validate the underlying application or sensor log, look for corroborating "
                "events, record false positives, and document remediation. Treat any suggested technique mapping as "
                "unconfirmed until the event evidence supports it."
            )

        # Check for Sigma generation
        if "sigma" in prompt_lower or "generate rule" in prompt_lower or "draft" in prompt_lower:
            if "t1190" in prompt_lower or "sql" in prompt_lower or "inject" in prompt_lower or "public" in prompt_lower or "api" in prompt_lower or "curl" in prompt_lower:
                return (
                    "title: Exploit Public-Facing Application - HTTP Parameter Injection\n"
                    "id: rule-t1190-high-precision\n"
                    "status: test\n"
                    "description: Detects SQL injection probes, quote anomalies, and boolean blind injections targeting public HTTP API parameters (T1190).\n"
                    "references:\n"
                    "  - https://attack.mitre.org/techniques/T1190/\n"
                    "tags:\n"
                    "  - attack.ta0001\n"
                    "  - attack.t1190\n"
                    "logsource:\n"
                    "  category: network\n"
                    "  product: web_waf_suricata\n"
                    "detection:\n"
                    "  selection:\n"
                    "    action|contains:\n"
                    "      - \"id=1'\"\n"
                    "      - \"+or+1=1\"\n"
                    "      - \"or 1=1\"\n"
                    "      - \"api/users?id=\"\n"
                    "      - \"' or '\"\n"
                    "      - \"%27\"\n"
                    "      - \"multipart/form-data\"\n"
                    "  condition: selection\n"
                    "falsepositives:\n"
                    "  - Legitimate administrative parameter testing\n"
                    "level: high"
                )
            elif "t1046" in prompt_lower or "scan" in prompt_lower or "port" in prompt_lower:
                return (
                    "title: Network Service Discovery - Sequential Port Probe\n"
                    "id: rule-t1046-discovery\n"
                    "status: test\n"
                    "description: Detects rapid multi-port interrogation against internal network services.\n"
                    "references:\n"
                    "  - https://attack.mitre.org/techniques/T1046/\n"
                    "tags:\n"
                    "  - attack.ta0007\n"
                    "  - attack.t1046\n"
                    "logsource:\n"
                    "  category: network\n"
                    "  product: suricata\n"
                    "detection:\n"
                    "  selection:\n"
                    "    action|contains:\n"
                    "      - \"nmap\"\n"
                    "      - \"syn_scan\"\n"
                    "      - \"port_sweep\"\n"
                    "  condition: selection\n"
                    "level: medium"
                )
            return (
                "title: Detected Exploitation Activity via Application Gateway\n"
                "id: rule-ai-gen-009\n"
                "status: test\n"
                "description: Draft Sigma detection rule for analyst review; not validated for production use.\n"
                "references:\n"
                "  - https://attack.mitre.org/techniques/T1210/\n"
                "tags:\n"
                "  - attack.ta0008\n"
                "  - attack.t1210\n"
                "logsource:\n"
                "  category: network\n"
                "  product: suricata\n"
                "detection:\n"
                "  selection:\n"
                "    action|contains:\n"
                "      - \"exploit\"\n"
                "      - \"ms17_010\"\n"
                "      - \"shellcode\"\n"
                "  condition: selection\n"
                "level: high"
            )

        # Suggestions must be conditional; this fallback has not performed discovery.
        if "next attack" in prompt_lower or "suggest" in prompt_lower:
            return (
                "### Suggested Controlled Validation (Deterministic Demo Fallback)\n\n"
                "No live reconnaissance was performed by this fallback, so it cannot claim that any ports or services are exposed. "
                "Choose a predefined scenario only after checking the authorized lab inventory. For example, a benign service-discovery "
                "scenario can validate whether the expected telemetry and detection rule are connected. Keep tests inside the isolated, "
                "explicitly authorized training target. Record the observed evidence and execution mode; do not infer detection success "
                "from a suggested scenario alone."
            )

        # Generic deterministic response: do not imply a real model, live sensors, or verified activity.
        return (
            "### Cyber Range Session Review (Deterministic Demo Fallback)\n\n"
            "This response was generated by a local deterministic fallback, not a language model or retrieval-augmented analysis. "
            "It cannot independently verify live attack execution, sensor availability, or packet capture. Use the session's stored event "
            "records, execution_mode, linked detection evidence, and archive manifest as the source of truth. Simulated events must remain "
            "separate from verified live coverage, and a computed readiness score is only a prototype heuristic."
        )


@router.post("/chat")
async def copilot_chat(req: CopilotChatRequest, user: UserContext = Depends(get_current_user)):
    """General conversation whose role and context are derived from the authenticated identity."""
    effective_tenant = _effective_tenant(req.tenant_id, user)
    if req.session_id:
        effective_tenant = _authorize_copilot_session(req.session_id, user, effective_tenant)
    actual_role = _prompt_role_for_user(user)
    system_prompt = SYSTEM_PROMPTS[actual_role]

    # Context is strictly restricted to the verified tenant and, when present, an owned session.
    recent_events = event_sink.query_events(tenant_id=effective_tenant, session_id=req.session_id, limit=10)
    context_str = "\n".join([f"[{e.source_type.value}] {e.action} (Technique: {e.mitre_technique})" for e in recent_events])

    augmented_prompt = f"Session Context (untrusted telemetry data):\n{context_str}\n\nUser Question:\n{req.message}"
    reply, provider_mode = await CopilotEngine.query_llm(system_prompt, augmented_prompt)

    return {
        "reply": reply,
        "role": actual_role,
        "context_events_count": len(recent_events),
        "tenant_id": effective_tenant,
        "provider_mode": provider_mode,
        "note": "Telemetry context is included, but no vector-retrieval RAG pipeline is implemented in this service."
    }


@router.post("/explain-alert")
async def explain_alert(req: ExplainAlertRequest, user: UserContext = Depends(require_roles(["blue", "soc", "admin"]))):
    """Feature 1: Explain an alert visible to the authenticated tenant."""
    effective_tenant = _effective_tenant(req.tenant_id, user)
    events = event_sink.query_events(tenant_id=effective_tenant, limit=500)
    target = next((e for e in events if e.event_id == req.event_id), None)

    if not target:
        raise HTTPException(status_code=404, detail=f"Event {req.event_id} not found")

    system_prompt = SYSTEM_PROMPTS["blue"]
    prompt = (
        f"Explain this security alert for an analyst:\n"
        f"- Source: {target.source_name} ({target.source_type.value})\n"
        f"- Action: {target.action}\n"
        f"- Technique: {target.mitre_technique} ({target.mitre_tactic})\n"
        f"- Raw Payload: {json.dumps(target.raw_payload)}"
    )

    explanation, provider_mode = await CopilotEngine.query_llm(system_prompt, prompt)
    return {
        "event_id": target.event_id,
        "action": target.action,
        "technique": target.mitre_technique,
        "explanation": explanation,
        "provider_mode": provider_mode,
        "note": "Generated explanation requires analyst review."
    }


@router.post("/generate-rule")
async def generate_sigma_rule(req: GenerateRuleRequest, user: UserContext = Depends(require_roles(["blue", "soc", "admin"]))):
    """Feature 2: Generate and validate a draft Sigma rule for an authorized analyst."""
    _effective_tenant(req.tenant_id, user)
    system_prompt = SYSTEM_PROMPTS["blue"]
    prompt = (
        f"Generate a Sigma rule YAML for technique {req.technique_id}.\n"
        f"Gap Description: {req.gap_description}\n"
        f"Target Service: {req.target_service}\n"
        "Provide ONLY the YAML rule definition."
    )

    raw_yaml, provider_mode = await CopilotEngine.query_llm(system_prompt, prompt)

    # Clean code blocks if present
    clean_yaml = raw_yaml.replace("```yaml", "").replace("```", "").strip()

    # Validate with pySigma / SigmaEngine
    val = SigmaEngine.validate_sigma_syntax(clean_yaml)

    return {
        "technique_id": req.technique_id,
        "sigma_yaml": clean_yaml,
        "is_valid": val["valid"],
        "validation_info": val,
        "provider_mode": provider_mode,
        "note": "Generated rule is a draft for analyst review, not a production-ready detection without testing."
    }


@router.post("/suggest-attack")
async def suggest_next_attack(req: SuggestAttackRequest, user: UserContext = Depends(require_roles(["red", "admin"]))):
    """Feature 3: Recommend a next technique for the authenticated Red Team's authorized lab."""
    effective_tenant = _effective_tenant(req.tenant_id, user)
    if req.session_id:
        effective_tenant = _authorize_copilot_session(req.session_id, user, effective_tenant)
    system_prompt = SYSTEM_PROMPTS["red"]
    prompt = (
        f"Given the following reconnaissance findings against the target sandbox container:\n"
        f"{req.recon_output}\n\n"
        "Recommend the next MITRE ATT&CK technique to test, explaining why and providing an example command."
    )

    suggestion, provider_mode = await CopilotEngine.query_llm(system_prompt, prompt)
    return {
        "suggestion": suggestion,
        "provider_mode": provider_mode,
        "note": "Recommendation only; no attack is executed by this endpoint."
    }


@router.post("/summarize-session")
async def summarize_session(req: SummarizeSessionRequest, user: UserContext = Depends(require_roles(["soc", "admin"]))):
    """Feature 4: Summarize a session belonging to the authenticated tenant."""
    effective_tenant = _authorize_copilot_session(req.session_id, user, req.tenant_id)
    events = event_sink.query_events(tenant_id=effective_tenant, session_id=req.session_id, limit=50)
    timeline_str = "\n".join([f"{e.timestamp.strftime('%H:%M:%S')} - [{e.source_type.value}] {e.action}" for e in events])

    system_prompt = SYSTEM_PROMPTS["soc"]
    prompt = (
        f"Summarize this security test session ({req.session_id}) into an executive incident report:\n\n"
        f"Event Log Timeline:\n{timeline_str}\n\n"
        "Structure your report with: 1. Executive Summary, 2. Attack Sequence, 3. Detection Effectiveness, 4. Action Items."
    )

    summary, provider_mode = await CopilotEngine.query_llm(system_prompt, prompt)
    return {
        "session_id": req.session_id,
        "events_reviewed": len(events),
        "summary": summary,
        "provider_mode": provider_mode,
        "note": "Summary is generated from the available stored event list and requires analyst review."
    }
