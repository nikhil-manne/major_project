#!/usr/bin/env python3
"""Run the prepared demo through the real HTTP API of a running local backend.

This script does not call FastAPI route functions directly (their Depends defaults
are only resolved by FastAPI itself). Results are labelled by the API's actual
execution_mode. It is not a live-attack or production-verification script.
"""
from __future__ import annotations

import asyncio
import os
import sys
from urllib.parse import urlparse

import httpx

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
from shared.config import settings  # noqa: E402

TENANT_ID = "00000000-0000-0000-0000-000000000123"
BASE_URL = os.getenv("CYBERRANGE_API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def build_auth_headers() -> dict[str, str]:
    token = os.getenv("CYBERRANGE_BEARER_TOKEN", "").strip()
    if token:
        return {"Authorization": f"Bearer {token}"}

    host = (urlparse(BASE_URL).hostname or "").lower()
    loopback_host = host in {"localhost", "127.0.0.1", "::1", "testserver"}
    if settings.DEV_AUTH_ENABLED and loopback_host:
        return {
            "X-Dev-Role": "admin",
            "X-Dev-Tenant": TENANT_ID,
            "X-Dev-User": "local-demo-runner",
        }
    raise RuntimeError(
        "No accepted authentication configured. Set CYBERRANGE_BEARER_TOKEN to a valid "
        "Keycloak token, or enable DEV_AUTH_ENABLED only for a loopback-only local demo."
    )


async def request_json(client: httpx.AsyncClient, method: str, path: str, **kwargs):
    response = await client.request(method, path, **kwargs)
    if response.is_error:
        raise RuntimeError(f"{method} {path} failed ({response.status_code}): {response.text[:700]}")
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{method} {path} returned non-JSON content") from exc


async def run_end_to_end_demo() -> int:
    print("=" * 72)
    print("UNIFIED CYBER RANGE — API-DRIVEN LOCAL DEMONSTRATION")
    print("=" * 72)
    print(f"API: {BASE_URL}")

    headers = build_auth_headers()
    timeout = httpx.Timeout(45.0, connect=5.0)
    async with httpx.AsyncClient(base_url=BASE_URL, headers=headers, timeout=timeout) as client:
        health = await request_json(client, "GET", "/api/v1/system/health")
        print(f"\n[1/6] Backend health: {health.get('status')} (configured mode: {health.get('execution_mode')})")

        demo = await request_json(client, "POST", "/api/v1/system/demo-seed")
        session_id = demo.get("session_id")
        if not session_id:
            raise RuntimeError("Demo seed returned no session_id")
        print(f"[2/6] Demo session: {session_id}")
        print(f"      execution_mode={demo.get('execution_mode')}; live_steps={demo.get('attacks_executed_live', 0)}; "
              f"simulated_steps={demo.get('simulated_steps', 0)}; blocked_steps={demo.get('blocked_steps', 0)}")
        print(f"      detections_fired={demo.get('detections_fired', 0)}; "
              f"readiness_score={demo.get('readiness_score')} (heuristic only; not production certification)")

        coverage = await request_json(client, "GET", "/api/v1/validation/coverage", params={"session_id": session_id})
        print(f"[3/6] Coverage: tested={coverage.get('tested_techniques')}; covered={coverage.get('covered_count')}; "
              f"gaps={coverage.get('gap_count')}; simulated={coverage.get('simulated_count')}")

        manifest = await request_json(client, "POST", f"/api/v1/replay/archive/{session_id}")
        capture = manifest.get("network_capture", {})
        print(f"[4/6] Archive: {manifest.get('status', 'created')}; packet_capture={capture.get('status', 'not reported')}; "
              f"packets={capture.get('packet_count', 0)}")

        replay = await request_json(
            client, "POST", f"/api/v1/replay/execute/{session_id}",
            json={"session_id": session_id, "test_detection_rules": True},
        )
        print(f"[5/6] Evidence replay: re-emitted_attack_events={replay.get('attacks_re_emitted', 0)}; "
              f"replay_detections={replay.get('detections_triggered', 0)}")

        copilot = await request_json(
            client, "POST", "/api/v1/copilot/chat",
            json={"message": "Summarize the evidence and explain the main limitation of this demo.", "session_id": session_id},
        )
        print(f"[6/6] Copilot provider mode: {copilot.get('provider_mode')}")
        print("      " + (copilot.get("reply", "No response").replace("\n", " ")[:250]))

    print("\nDEMO COMPLETE — this confirms only the reported local workflow.")
    print("Live attack execution, real sensor capture, and production infrastructure must be verified separately.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(run_end_to_end_demo()))
    except (httpx.HTTPError, RuntimeError) as exc:
        print(f"DEMO FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
