"""
Event Normalizer & Adapters
Transforms heterogeneous raw sensor/tool inputs into the unified NormalizedEvent schema.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid
import re

from shared.schema import NormalizedEvent, SourceType, Severity, Outcome


class IngestionNormalizer:
    @staticmethod
    def normalize_event(
        raw_data: Dict[str, Any],
        source_hint: Optional[str] = None,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        build_id: Optional[str] = None
    ) -> NormalizedEvent:
        """Normalize a payload using trusted tenant/session/build context from the caller."""
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("A trusted tenant_id is required to normalize telemetry")
        tenant_id = tenant_id.strip()

        # If already normalized format, validate and return
        if "source_type" in raw_data and "action" in raw_data and "source_name" in raw_data:
            return NormalizedEvent(
                event_id=raw_data.get("event_id") or str(uuid.uuid4()),
                tenant_id=tenant_id,
                session_id=session_id,
                scenario_id=raw_data.get("scenario_id"),
                build_id=build_id,
                timestamp=raw_data.get("timestamp") or datetime.now(timezone.utc),
                source_type=raw_data["source_type"],
                source_name=raw_data["source_name"],
                actor=raw_data.get("actor", "system"),
                action=raw_data["action"],
                mitre_tactic=raw_data.get("mitre_tactic"),
                mitre_technique=raw_data.get("mitre_technique"),
                severity=raw_data.get("severity", Severity.MEDIUM),
                outcome=raw_data.get("outcome"),
                replay=raw_data.get("replay", False),
                raw_payload=raw_data.get("raw_payload", raw_data)
            )

        source = (source_hint or raw_data.get("source") or "").lower()

        # 1. Falco Host Security Adapter
        if source == "falco" or "output_fields" in raw_data or "falco" in str(raw_data.get("rule", "")).lower():
            return IngestionNormalizer._adapt_falco(raw_data, tenant_id, session_id, build_id)

        # 2. Suricata Network Security Adapter
        if source == "suricata" or "event_type" in raw_data and raw_data.get("event_type") == "alert":
            return IngestionNormalizer._adapt_suricata(raw_data, tenant_id, session_id, build_id)

        # 3. Metasploit Attack Adapter
        if source == "metasploit" or "msf_module" in raw_data or "module" in raw_data:
            return IngestionNormalizer._adapt_metasploit(raw_data, tenant_id, session_id, build_id)

        # 4. Nmap Recon Adapter
        if source == "nmap" or "nmap_command" in raw_data or "scan_type" in raw_data:
            return IngestionNormalizer._adapt_nmap(raw_data, tenant_id, session_id, build_id)

        # 5. Generic / Fallback Adapter
        return IngestionNormalizer._adapt_generic(raw_data, source_hint, tenant_id, session_id, build_id)

    @staticmethod
    def _adapt_falco(raw: Dict[str, Any], tenant_id: str, session_id: Optional[str], build_id: Optional[str]) -> NormalizedEvent:
        rule_name = raw.get("rule", "Runtime Syscall Alert")
        output = raw.get("output", f"Falco detected: {rule_name}")
        priority = str(raw.get("priority", "Notice")).lower()

        severity_map = {
            "emergency": Severity.CRITICAL,
            "critical": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warning": Severity.HIGH,
            "notice": Severity.MEDIUM,
            "info": Severity.LOW,
            "debug": Severity.LOW
        }
        severity = severity_map.get(priority, Severity.MEDIUM)

        # Infer MITRE technique from common Falco alerts
        mitre_tactic = "TA0002"  # Execution
        mitre_technique = "T1059"  # Command & Scripting Interpreter
        if "shell" in rule_name.lower() or "terminal" in rule_name.lower():
            mitre_technique = "T1059"
            mitre_tactic = "TA0002"
        elif "privilege" in rule_name.lower() or "setuid" in rule_name.lower():
            mitre_technique = "T1078"
            mitre_tactic = "TA0004"
        elif "cron" in rule_name.lower() or "scheduled" in rule_name.lower():
            mitre_technique = "T1053"
            mitre_tactic = "TA0003"
        elif "read sensitive" in rule_name.lower() or "shadow" in rule_name.lower() or "passwd" in rule_name.lower():
            mitre_technique = "T1003"
            mitre_tactic = "TA0006"

        return NormalizedEvent(
            tenant_id=tenant_id,
            session_id=session_id,
            build_id=build_id,
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.HOST,
            source_name="falco",
            actor=raw.get("output_fields", {}).get("user.name", "system"),
            action=f"Host Sensor: {output}",
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            severity=severity,
            outcome=Outcome.DETECTED,
            replay=raw.get("replay", False),
            raw_payload=raw
        )

    @staticmethod
    def _adapt_suricata(raw: Dict[str, Any], tenant_id: str, session_id: Optional[str], build_id: Optional[str]) -> NormalizedEvent:
        alert = raw.get("alert", {})
        signature = alert.get("signature", "Suricata Network Intrusion Alert")
        severity_val = alert.get("severity", 2)
        severity = Severity.HIGH if severity_val <= 1 else (Severity.MEDIUM if severity_val == 2 else Severity.LOW)

        src_ip = raw.get("src_ip", "0.0.0.0")
        dest_ip = raw.get("dest_ip", "0.0.0.0")
        proto = raw.get("proto", "TCP")

        mitre_technique = "T1210"
        mitre_tactic = "TA0008"
        if "portscan" in signature.lower() or "recon" in signature.lower():
            mitre_technique = "T1046"
            mitre_tactic = "TA0007"
        elif "sql" in signature.lower() or "sqli" in signature.lower():
            mitre_technique = "T1190"
            mitre_tactic = "TA0001"

        return NormalizedEvent(
            tenant_id=tenant_id,
            session_id=session_id,
            build_id=build_id,
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.NETWORK,
            source_name="suricata",
            actor=f"{src_ip}",
            action=f"Network Sensor: {signature} ({proto} {src_ip} -> {dest_ip})",
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            severity=severity,
            outcome=Outcome.DETECTED,
            replay=raw.get("replay", False),
            raw_payload=raw
        )

    @staticmethod
    def _adapt_metasploit(raw: Dict[str, Any], tenant_id: str, session_id: Optional[str], build_id: Optional[str]) -> NormalizedEvent:
        module = raw.get("module") or raw.get("msf_module") or "exploit/generic"
        target = raw.get("target", "target-sandbox")
        result = raw.get("result", "exploit sent")
        mitre_tactic = raw.get("mitre_tactic", "TA0008")
        mitre_technique = raw.get("mitre_technique", "T1210")

        return NormalizedEvent(
            tenant_id=tenant_id,
            session_id=session_id,
            scenario_id=raw.get("scenario_id"),
            build_id=build_id,
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.ATTACK,
            source_name="metasploit",
            actor=raw.get("actor", "redteam_operator"),
            action=f"Metasploit: {module} against {target} ({result})",
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            severity=Severity.HIGH,
            outcome=Outcome.SUCCEEDED if "opened" in str(result).lower() or "success" in str(result).lower() else Outcome.BLOCKED,
            replay=raw.get("replay", False),
            raw_payload=raw
        )

    @staticmethod
    def _adapt_nmap(raw: Dict[str, Any], tenant_id: str, session_id: Optional[str], build_id: Optional[str]) -> NormalizedEvent:
        target = raw.get("target", "target-sandbox")
        ports = raw.get("open_ports", [])
        command = raw.get("command", f"nmap -sV {target}")

        return NormalizedEvent(
            tenant_id=tenant_id,
            session_id=session_id,
            scenario_id=raw.get("scenario_id"),
            build_id=build_id,
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.ATTACK,
            source_name="nmap",
            actor=raw.get("actor", "redteam_operator"),
            action=f"Recon: {command} found {len(ports)} open ports: {ports}",
            mitre_tactic="TA0007",
            mitre_technique="T1046",
            severity=Severity.LOW,
            outcome=Outcome.SUCCEEDED,
            replay=raw.get("replay", False),
            raw_payload=raw
        )

    @staticmethod
    def _adapt_generic(raw: Dict[str, Any], source_hint: Optional[str], tenant_id: str, session_id: Optional[str], build_id: Optional[str]) -> NormalizedEvent:
        msg = raw.get("message") or raw.get("log") or raw.get("action") or str(raw)
        src = source_hint or raw.get("source_name") or "generic_sensor"
        return NormalizedEvent(
            tenant_id=tenant_id,
            session_id=session_id,
            scenario_id=raw.get("scenario_id"),
            build_id=build_id,
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.HOST,
            source_name=src,
            actor=raw.get("actor", "system"),
            action=str(msg)[:500],
            mitre_tactic=raw.get("mitre_tactic"),
            mitre_technique=raw.get("mitre_technique"),
            severity=Severity.MEDIUM,
            outcome=None,
            replay=raw.get("replay", False),
            raw_payload=raw
        )


class KafkaNormalizerWorker:
    """
    Background worker that consumes raw.* topics from Kafka,
    normalizes payloads via IngestionNormalizer, and publishes
    canonical events into normalized.events.
    """
    def __init__(self):
        self.running = False
        self.task = None

    async def run(self):
        from shared.kafka_client import KafkaConsumerBase, kafka_producer
        from shared.config import settings
        from services.ingestion.opensearch_sink import event_sink

        consumer = KafkaConsumerBase(
            topics=[
                settings.TOPIC_RAW_ATTACK,
                settings.TOPIC_RAW_NETWORK,
                settings.TOPIC_RAW_HOST,
                settings.TOPIC_RAW_SOC
            ],
            group_id="ingestion-normalizer-group"
        )
        self.running = True

        while self.running:
            try:
                msg = consumer.poll_message(timeout=0.5)
                if msg:
                    # Tenant binding must come from the trusted envelope emitted by an
                    # authenticated API or internal service. Never silently default an event
                    # with missing tenant metadata to the default tenant.
                    message_tenant = msg.get("tenant_id")
                    if not isinstance(message_tenant, str) or not message_tenant.strip():
                        continue
                    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else msg
                    source_hint = msg.get("source_type") or msg.get("source_hint") or payload.get("source_type") or payload.get("source")
                    norm_event = IngestionNormalizer.normalize_event(
                        raw_data=payload,
                        source_hint=source_hint,
                        tenant_id=message_tenant,
                        session_id=msg.get("session_id"),
                        build_id=msg.get("build_id")
                    )
                    # Produce to normalized.events
                    kafka_producer.produce(
                        topic=settings.TOPIC_NORMALIZED_EVENTS,
                        key=norm_event.session_id,
                        value=norm_event.model_dump()
                    )
                    # Index into OpenSearch sink
                    await event_sink.index_event(norm_event)
            except Exception:
                pass
            await asyncio.sleep(0.1)

        consumer.close()

    def start(self):
        import asyncio
        if not self.task or self.task.done():
            self.task = asyncio.create_task(self.run())

    def stop(self):
        self.running = False


normalizer_worker = KafkaNormalizerWorker()

