"""
Attack Scenario Runner & Asciinema Terminal Recorder
Executes MITRE-mapped attack playbooks against real Kubernetes toolbox pods or simulated targets,
binds commands to the verified session target endpoint, captures execution evidence,
and emits telemetry to Kafka raw.attack and OpenSearch event sink.
"""
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
import yaml

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.kafka_client import kafka_producer
from shared.config import settings
from shared.db import db_context, SessionModel, Lab
from services.ingestion.opensearch_sink import event_sink
from services.orchestrator.k8s_client import k8s_client

logger = logging.getLogger("cyberrange.attack_runner")

SCENARIOS_DIR = os.path.join(os.path.dirname(__file__), "scenarios")


class AttackScenarioRunner:
    @staticmethod
    def load_available_scenarios() -> List[Dict[str, Any]]:
        scenarios = []
        if not os.path.exists(SCENARIOS_DIR):
            return scenarios

        for file in os.listdir(SCENARIOS_DIR):
            if file.endswith(".yaml") or file.endswith(".yml"):
                path = os.path.join(SCENARIOS_DIR, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        data["file"] = file
                        scenarios.append(data)
                except Exception:
                    pass
        return scenarios

    @staticmethod
    def check_scenario_applicability(scenario: Dict[str, Any], lab: Optional[Lab]) -> Tuple[bool, str]:
        """Verifies if the scenario's required services match the lab configuration."""
        required = scenario.get("required_services") or []
        if not required or not lab:
            return True, "Scenario applicable to target"

        lab_ports = [str(p) for p in (getattr(lab, "ports", []) or [])]
        dockerfile_text = (lab.dockerfile_content or "").lower()
        compose_text = (lab.compose_content or "").lower()
        all_text = dockerfile_text + " " + compose_text

        # Check if any required service or port keyword is present in lab definition
        has_match = False
        for req in required:
            req_str = str(req).lower()
            if req_str in lab_ports or req_str in all_text:
                has_match = True
                break

        if not has_match and lab_ports:
            # If lab has explicitly declared ports and none match the required services
            return False, f"Target lab '{lab.name}' does not expose required service {required} (detected ports: {lab_ports})"

        return True, "Scenario applicable"

    @staticmethod
    async def execute_scenario(
        scenario_id: str,
        session_id: str,
        tenant_id: str,
        build_id: Optional[str] = None,
        operator: str = "redteam_operator"
    ) -> Dict[str, Any]:
        """
        Executes an attack playbook against a sandbox session:
        - Resolves the exact target endpoint from the active session
        - Validates target applicability against lab services
        - Executes allowlisted commands inside the toolbox pod via K8s exec API
        - Captures real command output, exit status, and timestamps
        - Emits events with truthful provenance (live vs simulated)
        - Generates Asciinema terminal cast
        """
        scenarios = AttackScenarioRunner.load_available_scenarios()
        selected = next((s for s in scenarios if s.get("id") == scenario_id), None)
        if not selected:
            raise ValueError(f"Scenario '{scenario_id}' not found")

        # 1. Resolve session and target details from database
        target_endpoint = "target-pod"
        target_image = "unknown"
        lab_id = None
        lab_obj = None
        session_mode = "simulated"

        with db_context() as db:
            session_row = db.query(SessionModel).filter_by(id=session_id).first()
            if session_row:
                target_endpoint = session_row.target_endpoint or f"target-app.{session_row.namespace}.svc.cluster.local"
                target_image = session_row.target_image
                lab_id = session_row.lab_id
                session_mode = getattr(session_row, "execution_mode", "simulated")
                if lab_id:
                    lab_obj = db.query(Lab).filter_by(id=lab_id).first()

        # 2. Applicability check
        is_applicable, reason = AttackScenarioRunner.check_scenario_applicability(selected, lab_obj)

        events_generated: List[NormalizedEvent] = []
        cast_records: List[List[Any]] = [
            {"version": 2, "width": 120, "height": 36, "timestamp": int(datetime.now(timezone.utc).timestamp())}
        ]

        elapsed_sec = 0.0

        for step in selected.get("steps", []):
            raw_action = step.get("action", "")
            step_tool = step.get("tool", "unknown")
            step_delay = step.get("delay_ms", 500) / 1000.0
            canned_output = step.get("expected_output", "")

            # Inject the verified target endpoint
            effective_action = (
                raw_action.replace("{TARGET_ENDPOINT}", target_endpoint)
                .replace("{TARGET}", target_endpoint)
                .replace("target-pod", target_endpoint)
            )

            if not is_applicable:
                # Mark step as not applicable based on lab evidence
                mode = "not_applicable"
                output = f"NOT APPLICABLE: {reason}"
                step_outcome = Outcome.NOT_APPLICABLE
                provenance = "simulated"
                exit_code = 0
            else:
                # Execute in toolbox pod if accessible
                real_exec = k8s_client.exec_command_in_toolbox(session_id, effective_action, target_endpoint=target_endpoint)
                mode = real_exec.get("execution_mode", "simulated")
                exit_code = real_exec.get("exit_code")

                if mode == "live":
                    output = real_exec.get("output", "")
                    step_outcome = Outcome.SUCCEEDED if exit_code == 0 else (Outcome.FAILED if exit_code is not None else Outcome.INCONCLUSIVE)
                    provenance = "live"
                elif mode == "blocked":
                    output = real_exec.get("output", "Command blocked by security allowlist")
                    step_outcome = Outcome.BLOCKED
                    provenance = "failed"
                else:
                    # Explicitly simulated
                    output = f"SIMULATED OUTPUT (not observed on target '{target_endpoint}'): {canned_output}"
                    step_outcome = Outcome.SIMULATED
                    provenance = "simulated"

            await asyncio.sleep(min(step_delay, 0.3))
            elapsed_sec += step_delay

            # Record terminal prompt & command in asciinema format
            cast_records.append([round(elapsed_sec, 2), "o", f"\r\n\x1b[31;1mredteam@toolbox:~\x1b[0m$ {effective_action}\r\n"])
            elapsed_sec += 0.2
            cast_records.append([round(elapsed_sec, 2), "o", f"{output}\r\n"])

            # Create Normalized Attack Event with truthful provenance
            event = NormalizedEvent(
                tenant_id=tenant_id,
                session_id=session_id,
                scenario_id=scenario_id,
                build_id=build_id,
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.ATTACK,
                source_name=step_tool,
                actor=operator,
                action=effective_action,
                mitre_tactic=selected.get("mitre_tactic"),
                mitre_technique=selected.get("mitre_technique"),
                severity=Severity.HIGH,
                outcome=step_outcome,
                provenance=provenance,
                raw_payload={
                    "step": step.get("step"),
                    "output": output,
                    "target": target_endpoint,
                    "target_endpoint": target_endpoint,
                    "lab_id": lab_id,
                    "target_image": target_image,
                    "live_executed": (mode == "live"),
                    "execution_mode": mode,
                    "exit_code": exit_code,
                    "applicable": is_applicable,
                    "outcome_note": "Execution status captures command output; verified vulnerability confirmation requires blue telemetry or exploit validation."
                }
            )

            # Publish to Kafka raw.attack topic
            kafka_producer.produce(
                topic=settings.TOPIC_RAW_ATTACK,
                key=session_id,
                value=event.model_dump()
            )

            # Index to OpenSearch / Event Sink
            await event_sink.index_event(event)
            events_generated.append(event)

        modes = [e.raw_payload.get("execution_mode", "unknown") for e in events_generated]
        overall_mode = "live" if modes and all(m == "live" for m in modes) else ("simulated" if all(m == "simulated" for m in modes) else "mixed")

        return {
            "scenario_id": scenario_id,
            "name": selected.get("name"),
            "technique": selected.get("mitre_technique"),
            "tactic": selected.get("mitre_tactic"),
            "session_id": session_id,
            "target_endpoint": target_endpoint,
            "lab_id": lab_id,
            "steps_executed": len(events_generated),
            "execution_mode": overall_mode,
            "live_steps": sum(1 for m in modes if m == "live"),
            "simulated_steps": sum(1 for m in modes if m == "simulated"),
            "blocked_steps": sum(1 for m in modes if m == "blocked"),
            "not_applicable_steps": sum(1 for m in modes if m == "not_applicable"),
            "events": events_generated,
            "terminal_cast": cast_records
        }
