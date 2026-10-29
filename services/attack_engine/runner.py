"""
Attack Scenario Runner & Asciinema Terminal Recorder
Executes MITRE-mapped attack playbooks against real Kubernetes toolbox pods or simulated targets,
captures live stdout, and emits telemetry to Kafka raw.attack and OpenSearch event sink.
"""
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional
import yaml

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
from shared.kafka_client import kafka_producer
from shared.config import settings
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
    async def execute_scenario(
        scenario_id: str,
        session_id: str,
        tenant_id: str,
        build_id: Optional[str] = None,
        operator: str = "redteam_operator"
    ) -> Dict[str, Any]:
        """
        Executes an attack playbook against a sandbox session:
        - Tries to execute the command inside the real toolbox pod via K8s exec API
        - Captures real command output
        - Emits events to Kafka (raw.attack topic) and OpenSearch
        - Generates Asciinema terminal cast
        """
        scenarios = AttackScenarioRunner.load_available_scenarios()
        selected = next((s for s in scenarios if s.get("id") == scenario_id), None)
        if not selected:
            raise ValueError(f"Scenario '{scenario_id}' not found")

        events_generated: List[NormalizedEvent] = []
        cast_records: List[List[Any]] = [
            # Asciinema v2 header
            {"version": 2, "width": 120, "height": 36, "timestamp": int(datetime.now(timezone.utc).timestamp())}
        ]

        elapsed_sec = 0.0

        for step in selected.get("steps", []):
            step_action = step.get("action", "")
            step_tool = step.get("tool", "unknown")
            step_delay = step.get("delay_ms", 500) / 1000.0
            canned_output = step.get("expected_output", "")

            # Execute real command in toolbox pod if accessible
            real_exec = k8s_client.exec_command_in_toolbox(session_id, step_action)
            mode = real_exec.get("execution_mode", "simulated")
            if mode == "simulated":
                output = f"SIMULATED OUTPUT (not observed on a target): {canned_output}"
            else:
                output = real_exec.get("output", "")

            # Simulated pacing
            await asyncio.sleep(min(step_delay, 0.3))
            elapsed_sec += step_delay

            # Record terminal prompt & command in asciinema format
            cast_records.append([round(elapsed_sec, 2), "o", f"\r\n\x1b[31;1mredteam@toolbox:~\x1b[0m$ {step_action}\r\n"])
            elapsed_sec += 0.2
            cast_records.append([round(elapsed_sec, 2), "o", f"{output}\r\n"])

            # Create Normalized Attack Event
            event = NormalizedEvent(
                tenant_id=tenant_id,
                session_id=session_id,
                scenario_id=scenario_id,
                build_id=build_id,
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.ATTACK,
                source_name=step_tool,
                actor=operator,
                action=step_action,
                mitre_tactic=selected.get("mitre_tactic"),
                mitre_technique=selected.get("mitre_technique"),
                severity=Severity.HIGH,
                outcome=(
                    Outcome.SIMULATED if mode == "simulated"
                    else Outcome.BLOCKED if mode == "blocked"
                    else Outcome.INCONCLUSIVE
                ),
                raw_payload={
                    "step": step.get("step"),
                    "output": output,
                    "target": "target-sandbox",
                    "live_executed": real_exec.get("executed_live", False),
                    "execution_mode": mode,
                    "outcome_note": "Command output alone is not proof of a successful exploit."
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
            "steps_executed": len(events_generated),
            "execution_mode": overall_mode,
            "live_steps": sum(1 for m in modes if m == "live"),
            "simulated_steps": sum(1 for m in modes if m == "simulated"),
            "blocked_steps": sum(1 for m in modes if m == "blocked"),
            "events": events_generated,
            "terminal_cast": cast_records
        }
