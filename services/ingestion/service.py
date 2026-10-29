"""
Ingestion Service API
Provides endpoints to ingest raw security telemetry and stream normalized events.
"""
import asyncio
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query, BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from shared.schema import NormalizedEvent
from shared.auth import get_current_user, UserContext
from .normalizer import IngestionNormalizer
from .opensearch_sink import event_sink
from shared.db import db_context, SessionModel, BuildModel

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion & Data Plane"])

# SSE Subscriber queues
from shared.kafka_client import kafka_producer
from shared.config import settings

subscribers: List[tuple[asyncio.Queue, str]] = []


class RawIngestRequest(BaseModel):
    raw_payload: Dict[str, Any]
    source_hint: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    build_id: Optional[str] = None


async def broadcast_event(event: NormalizedEvent):
    """Notify all connected SSE subscribers of new normalized event."""
    data = event.model_dump_json()
    for queue, subscribed_tenant in subscribers[:]:
        if event.tenant_id != subscribed_tenant:
            continue
        try:
            queue.put_nowait(data)
        except Exception:
            if (queue, subscribed_tenant) in subscribers:
                subscribers.remove((queue, subscribed_tenant))




def _validate_event_references(session_id: Optional[str], build_id: Optional[str], tenant_id: str) -> None:
    """Prevent events from one tenant being attached to another tenant's session/build."""
    if not session_id and not build_id:
        return
    with db_context() as db:
        if session_id:
            session = db.query(SessionModel).filter_by(id=session_id, tenant_id=tenant_id).first()
            if not session:
                raise HTTPException(status_code=404, detail="Session not found in the authenticated tenant")
        if build_id:
            build = db.query(BuildModel).filter_by(id=build_id, tenant_id=tenant_id).first()
            if not build:
                raise HTTPException(status_code=404, detail="Build not found in the authenticated tenant")

def get_raw_topic(source_hint: Optional[str], raw_payload: Dict[str, Any]) -> str:
    s = (source_hint or raw_payload.get("source_type") or raw_payload.get("source") or "").lower()
    if "attack" in s or "metasploit" in s or "nmap" in s:
        return settings.TOPIC_RAW_ATTACK
    elif "network" in s or "suricata" in s or "pcap" in s:
        return settings.TOPIC_RAW_NETWORK
    elif "soc" in s or "analyst" in s:
        return settings.TOPIC_RAW_SOC
    return settings.TOPIC_RAW_HOST


@router.post("/raw", response_model=NormalizedEvent)
async def ingest_raw_event(req: RawIngestRequest, user: UserContext = Depends(get_current_user)):
    """
    Publish incoming raw telemetry into the appropriate Kafka raw.* topic,
    normalize the payload, index into OpenSearch, and stream to live consumers.
    """
    if req.tenant_id and req.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot ingest events for another tenant")
    eff_tenant = req.tenant_id if (req.tenant_id and user.role == "admin") else user.tenant_id
    _validate_event_references(req.session_id, req.build_id, eff_tenant)
    raw_topic = get_raw_topic(req.source_hint, req.raw_payload)

    # 1. Publish to Kafka raw.* topic
    kafka_producer.produce(
        topic=raw_topic,
        key=req.session_id,
        value={
            "payload": req.raw_payload,
            "source_hint": req.source_hint,
            "tenant_id": eff_tenant,
            "session_id": req.session_id,
            "build_id": req.build_id
        }
    )

    # 2. Normalize event
    event = IngestionNormalizer.normalize_event(
        raw_data=req.raw_payload,
        source_hint=req.source_hint,
        tenant_id=eff_tenant,
        session_id=req.session_id,
        build_id=req.build_id
    )

    # 3. Publish to normalized.events
    kafka_producer.produce(
        topic=settings.TOPIC_NORMALIZED_EVENTS,
        key=event.session_id,
        value=event.model_dump()
    )

    await event_sink.index_event(event)
    await broadcast_event(event)
    return event


@router.post("/normalized", response_model=NormalizedEvent)
async def ingest_normalized_event(event: NormalizedEvent, user: UserContext = Depends(get_current_user)):
    """Directly ingest an event only within the authenticated tenant."""
    if event.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot ingest events for another tenant")
    _validate_event_references(event.session_id, event.build_id, event.tenant_id)
    kafka_producer.produce(
        topic=settings.TOPIC_NORMALIZED_EVENTS,
        key=event.session_id,
        value=event.model_dump()
    )
    await event_sink.index_event(event)
    await broadcast_event(event)
    return event


@router.post("/batch", response_model=Dict[str, Any])
async def ingest_batch(events: List[RawIngestRequest], user: UserContext = Depends(get_current_user)):
    """Batch ingest telemetry events; reject the entire batch if any tenant is unauthorized."""
    for item in events:
        if item.tenant_id and item.tenant_id != user.tenant_id and user.role != "admin":
            raise HTTPException(status_code=403, detail="Batch contains an event for another tenant")
        eff_tenant = item.tenant_id if (item.tenant_id and user.role == "admin") else user.tenant_id
        _validate_event_references(item.session_id, item.build_id, eff_tenant)
    normalized_events = []
    for item in events:
        eff_tenant = item.tenant_id if (item.tenant_id and user.role == "admin") else user.tenant_id
        raw_topic = get_raw_topic(item.source_hint, item.raw_payload)
        kafka_producer.produce(
            topic=raw_topic,
            key=item.session_id,
            value={
                "payload": item.raw_payload,
                "source_hint": item.source_hint,
                "tenant_id": eff_tenant,
                "session_id": item.session_id,
                "build_id": item.build_id
            }
        )

        ev = IngestionNormalizer.normalize_event(
            raw_data=item.raw_payload,
            source_hint=item.source_hint,
            tenant_id=eff_tenant,
            session_id=item.session_id,
            build_id=item.build_id
        )
        kafka_producer.produce(
            topic=settings.TOPIC_NORMALIZED_EVENTS,
            key=ev.session_id,
            value=ev.model_dump()
        )
        await event_sink.index_event(ev)
        await broadcast_event(ev)
        normalized_events.append(ev)

    return {
        "status": "success",
        "ingested_count": len(normalized_events)
    }



# Query router for events
events_router = APIRouter(prefix="/api/v1/events", tags=["Normalized Events"])


@events_router.get("", response_model=List[NormalizedEvent])
async def get_events(
    tenant_id: Optional[str] = Query(None),
    session_id: Optional[str] = None,
    build_id: Optional[str] = None,
    source_type: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    user: UserContext = Depends(get_current_user),
):
    """Query normalized events within the authenticated tenant."""
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot query events for another tenant")
    return event_sink.query_events(tenant_id=eff_tenant, session_id=session_id, build_id=build_id, source_type=source_type, mitre_technique=mitre_technique, limit=limit)


@events_router.get("/stats")
async def get_event_stats(
    tenant_id: Optional[str] = Query(None),
    session_id: Optional[str] = None,
    user: UserContext = Depends(get_current_user),
):
    """Retrieve event statistics within the authenticated tenant."""
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot query stats for another tenant")
    return event_sink.get_stats(tenant_id=eff_tenant, session_id=session_id)


@events_router.get("/stream")
async def stream_live_events(user: UserContext = Depends(get_current_user)):
    """Tenant-scoped Server-Sent Events feed."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    subscription = (queue, user.tenant_id)
    subscribers.append(subscription)

    async def event_generator():
        try:
            yield ": connected\n\n"
            while True:
                data = await queue.get()
                yield f"data: {data}\n\n"
        except asyncio.CancelledError:
            if subscription in subscribers:
                subscribers.remove(subscription)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
