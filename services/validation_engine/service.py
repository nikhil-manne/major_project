"""
Validation Engine API
Provides outcome-based MITRE ATT&CK coverage calculation and Navigator layers.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query, Depends, HTTPException
from fastapi.responses import JSONResponse

from shared.mitre_data import MITRE_TACTICS, MITRE_TECHNIQUES
from services.ingestion.opensearch_sink import event_sink
from shared.auth import get_current_user, UserContext
from .navigator import ValidationEngine

router = APIRouter(prefix="/api/v1/validation", tags=["MITRE ATT&CK Validation Engine"])


@router.get("/coverage")
async def get_coverage(
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    build_id: Optional[str] = None,
    time_window_sec: float = Query(120.0, ge=10.0, le=600.0),
    user: UserContext = Depends(get_current_user),
):
    """
    Computes outcome-based MITRE ATT&CK coverage by comparing
    attacks executed against detections fired.
    """
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot validate coverage for another tenant")
    events = event_sink.query_events(
        tenant_id=eff_tenant,
        session_id=session_id,
        build_id=build_id,
        limit=1000
    )
    return ValidationEngine.calculate_coverage(events, time_window_sec=time_window_sec)


@router.get("/navigator-layer")
async def get_navigator_layer(
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    layer_name: str = "Cyber Range Security Validation Layer",
    user: UserContext = Depends(get_current_user),
):
    """Export standard MITRE ATT&CK Navigator v4.5 JSON layer for one tenant."""
    eff_tenant = tenant_id or user.tenant_id
    if eff_tenant != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Cannot export another tenant's coverage")
    events = event_sink.query_events(tenant_id=eff_tenant, session_id=session_id, limit=1000)
    cov = ValidationEngine.calculate_coverage(events)
    layer = ValidationEngine.generate_navigator_layer(cov, layer_name=layer_name)
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f"attachment; filename=navigator-layer-{session_id or 'all'}.json"}
    )


@router.get("/tactics")
async def get_tactics():
    """List all MITRE tactics in the reference catalogue."""
    return [
        {
            "id": tac["id"],
            "name": tac["name"],
            "short": tac["short"],
            "techniques": [t for t in MITRE_TECHNIQUES if t["tactic_id"] == tac["id"]]
        }
        for tac in MITRE_TACTICS.values()
    ]
