"""
Canonical Normalized Event Schema
Reflects docs/schema.md exactly.
Every service (attack, detection, replay, validation, copilot, ingestion) uses this shape.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field, field_serializer, field_validator


class SourceType(str, Enum):
    ATTACK = "attack"
    DETECTION = "detection"
    NETWORK = "network"
    HOST = "host"
    SOC_ACTION = "soc_action"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Outcome(str, Enum):
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    DETECTED = "detected"
    UNDETECTED = "undetected"
    SIMULATED = "simulated"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class Provenance(str, Enum):
    LIVE = "live"
    SIMULATED = "simulated"
    REPLAYED = "replayed"
    TEST_FIXTURE = "test_fixture"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(..., description="Tenant identifier (the configured tenant UUID)")
    session_id: Optional[str] = Field(None, description="Sandbox session id, null for pure production events")
    scenario_id: Optional[str] = Field(None, description="Scripted scenario id, if generated from scenario")
    build_id: Optional[str] = Field(None, description="CI/CD build id, for pre-release gate traceability")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: SourceType = Field(..., description="attack | detection | network | host | soc_action")
    source_name: str = Field(..., description="metasploit | falco | suricata | sigma_rule | analyst | etc.")
    actor: str = Field(..., description="redteam_user_1 | system | analyst_name")
    action: str = Field(..., description="Human or tool-readable command/alert/action string")
    mitre_tactic: Optional[str] = Field(None, description="e.g. TA0007, TA0001")
    mitre_technique: Optional[str] = Field(None, description="e.g. T1046, T1210")
    severity: Severity = Field(default=Severity.MEDIUM)
    outcome: Optional[Outcome] = Field(None, description="succeeded | blocked | detected | undetected | simulated | failed | not_applicable | None")
    provenance: str = Field(default="live", description="live | simulated | replayed | test_fixture | failed")
    replay: bool = Field(default=False, description="True if re-emitted by Replay Engine")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Untouched original payload")

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info) -> str:
        return dt.isoformat()

    @field_validator("timestamp", mode="before")
    def parse_timestamp(cls, value):
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except Exception:
                return datetime.now(timezone.utc)
        return value

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "event_id": "a1b2c3d4-0001",
                "tenant_id": "00000000-0000-0000-0000-000000000123",
                "session_id": "sess-9f2a",
                "scenario_id": "scn-brute-force-01",
                "build_id": None,
                "timestamp": "2026-10-22T10:15:03.120Z",
                "source_type": "attack",
                "source_name": "metasploit",
                "actor": "redteam_user_1",
                "action": "exploit/windows/smb/ms17_010_eternalblue",
                "mitre_tactic": "TA0001",
                "mitre_technique": "T1210",
                "severity": "high",
                "outcome": "succeeded",
                "replay": False,
                "raw_payload": {
                    "module": "ms17_010_eternalblue",
                    "target": "10.0.0.5",
                    "result": "session opened"
                }
            }
        }
    }


class SessionManifest(BaseModel):
    session_id: str
    tenant_id: str
    build_id: Optional[str] = None
    target_image: str
    status: str
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    total_events: int = 0
    attack_events: int = 0
    detection_events: int = 0
    techniques_exercised: list[str] = Field(default_factory=list)
    techniques_detected: list[str] = Field(default_factory=list)
    readiness_score: Optional[float] = None


class ReadinessScoreReport(BaseModel):
    session_id: Optional[str] = None
    build_id: Optional[str] = None
    tenant_id: str
    coverage_pct: float
    avg_detection_latency_sec: float
    unresolved_incidents: int
    score: float
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    breakdown: Dict[str, Any] = Field(default_factory=dict)
