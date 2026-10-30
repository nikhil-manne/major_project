"""
OpenSearch & In-Memory Storage Sink
Handles indexing, querying, and buffering of normalized events.
"""
from collections import deque
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import httpx

from shared.config import settings
from shared.schema import NormalizedEvent

logger = logging.getLogger("EventSink")


class EventSink:
    def __init__(self, opensearch_url: str = settings.OPENSEARCH_HOST):
        self.opensearch_url = opensearch_url.rstrip("/")
        # In-memory buffer is a fast cache. The SQLite/PostgreSQL event table is the durable fallback.
        self._memory_store: deque[NormalizedEvent] = deque(maxlen=10000)
        self.is_opensearch_live = False
        self.is_durable_store_live = False
        self._last_opensearch_check = 0.0

    async def check_health(self) -> bool:
        import time
        now = time.time()
        if now - self._last_opensearch_check < 10.0:
            return self.is_opensearch_live
        self._last_opensearch_check = now
        try:
            async with httpx.AsyncClient(timeout=0.6) as client:
                res = await client.get(f"{self.opensearch_url}/_cluster/health")
                self.is_opensearch_live = res.status_code == 200
                return self.is_opensearch_live
        except Exception:
            self.is_opensearch_live = False
            return False

    async def index_event(self, event: NormalizedEvent) -> bool:
        """Persist event to the local relational store, cache it, and opportunistically index OpenSearch."""
        self._memory_store.append(event)
        # Durable fallback is independent of Kafka/OpenSearch availability.
        try:
            from shared.db import db_context, NormalizedEventModel
            payload = json.loads(event.model_dump_json())
            with db_context() as db:
                existing = db.query(NormalizedEventModel).filter_by(event_id=event.event_id).first()
                if existing:
                    existing.event_payload = payload
                    existing.tenant_id = event.tenant_id
                    existing.session_id = event.session_id
                    existing.build_id = event.build_id
                    existing.timestamp = event.timestamp
                    existing.source_type = event.source_type.value
                    existing.mitre_technique = event.mitre_technique
                    existing.provenance = getattr(event, "provenance", "simulated")
                else:
                    db.add(NormalizedEventModel(
                        event_id=event.event_id,
                        tenant_id=event.tenant_id,
                        session_id=event.session_id,
                        build_id=event.build_id,
                        timestamp=event.timestamp,
                        source_type=event.source_type.value,
                        mitre_technique=event.mitre_technique,
                        provenance=getattr(event, "provenance", "simulated"),
                        event_payload=payload,
                    ))
                db.commit()
            self.is_durable_store_live = True
        except Exception as exc:
            self.is_durable_store_live = False
            logger.warning("Could not persist normalized event to relational store; it remains only in memory: %s", exc)

        # OpenSearch is optional; check health at a throttled interval instead of assuming it is live.
        if not await self.check_health():
            return self.is_durable_store_live

        index_date = event.timestamp.strftime("%Y.%m.%d")
        index_name = f"events-{index_date}"
        try:
            payload = json.loads(event.model_dump_json())
            async with httpx.AsyncClient(timeout=0.8) as client:
                res = await client.put(
                    f"{self.opensearch_url}/{index_name}/_doc/{event.event_id}",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                if res.status_code in (200, 201):
                    return True
                logger.warning("OpenSearch event write returned HTTP %s", res.status_code)
        except Exception as exc:
            self.is_opensearch_live = False
            logger.warning("OpenSearch event write failed; relational fallback remains available: %s", exc)
        return self.is_durable_store_live

    def _tenant_matches(self, t1: Optional[str], t2: Optional[str]) -> bool:
        if not t1 or not t2:
            return False
        if t1 == t2:
            return True
        aliases = {"org-123", "00000000-0000-0000-0000-000000000123"}
        return (t1 in aliases) and (t2 in aliases)

    def query_events(
        self,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        build_id: Optional[str] = None,
        source_type: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        limit: int = 100,
        replay_filter: Optional[bool] = None
    ) -> List[NormalizedEvent]:
        """Query cached and durable events with strict tenant/session filters and event-id de-duplication."""
        clean_tenant = tenant_id.strip() if tenant_id and tenant_id.strip() else None
        clean_session = session_id.strip() if session_id and session_id.strip() and session_id != "all" else None
        clean_build = build_id.strip() if build_id and build_id.strip() else None
        by_id: Dict[str, NormalizedEvent] = {}

        def matches(ev: NormalizedEvent) -> bool:
            if clean_tenant and not self._tenant_matches(ev.tenant_id, clean_tenant):
                return False
            if clean_session and ev.session_id != clean_session:
                return False
            if clean_build and ev.build_id != clean_build:
                return False
            if source_type and ev.source_type.value != source_type:
                return False
            if mitre_technique and ev.mitre_technique != mitre_technique:
                return False
            if replay_filter is not None and ev.replay != replay_filter:
                return False
            return True

        for event in self._memory_store:
            if matches(event):
                by_id[event.event_id] = event

        # Query the durable database so events survive process restarts and cache eviction.
        try:
            from shared.db import db_context, NormalizedEventModel
            with db_context() as db:
                query = db.query(NormalizedEventModel)
                if clean_tenant:
                    tenant_values = [clean_tenant]
                    if clean_tenant in {"org-123", "00000000-0000-0000-0000-000000000123"}:
                        tenant_values = ["org-123", "00000000-0000-0000-0000-000000000123"]
                    query = query.filter(NormalizedEventModel.tenant_id.in_(tenant_values))
                if clean_session:
                    query = query.filter(NormalizedEventModel.session_id == clean_session)
                if clean_build:
                    query = query.filter(NormalizedEventModel.build_id == clean_build)
                if source_type:
                    query = query.filter(NormalizedEventModel.source_type == source_type)
                if mitre_technique:
                    query = query.filter(NormalizedEventModel.mitre_technique == mitre_technique)
                # Session-specific queries are normally small. Bound broad historical retrievals.
                rows = query.order_by(NormalizedEventModel.timestamp.desc()).limit(max(limit * 4, 1000)).all()
                for row in rows:
                    try:
                        event = NormalizedEvent(**row.event_payload)
                        if matches(event):
                            by_id[event.event_id] = event
                    except Exception:
                        logger.exception("Skipping invalid durable normalized event %s", row.event_id)
        except Exception as exc:
            logger.debug("Durable event query unavailable; using memory cache: %s", exc)

        ordered = sorted(by_id.values(), key=lambda ev: ev.timestamp, reverse=True)
        return ordered[:max(0, limit)]

    def get_stats(self, tenant_id: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
        events = self.query_events(tenant_id=tenant_id, session_id=session_id, limit=5000)
        by_source: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_technique: Dict[str, int] = {}

        for ev in events:
            st = ev.source_type.value
            sev = ev.severity.value
            by_source[st] = by_source.get(st, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if ev.mitre_technique:
                by_technique[ev.mitre_technique] = by_technique.get(ev.mitre_technique, 0) + 1

        return {
            "total_events": len(events),
            "by_source": by_source,
            "by_severity": by_severity,
            "by_technique": by_technique
        }


# Singleton instance
event_sink = EventSink()
