"""Repeatable local evaluation of the Cyber Range prototype.

This script deliberately evaluates the simulation/local-database profile. It does not
claim to test Kubernetes, Kafka, PostgreSQL, OpenSearch, MinIO, real sensors, live
attacks, or a production Keycloak deployment. It creates temporary local state.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Force the explicitly safe local profile before importing settings or app modules.
os.environ["DEV_AUTH_ENABLED"] = "false"
os.environ["ATTACK_EXECUTION_MODE"] = "simulation"
os.environ["ALLOW_SIMULATED_SANDBOX"] = "true"
os.environ["HOST"] = "127.0.0.1"
os.environ["ANTHROPIC_API_KEY"] = "dev_placeholder"

RUNTIME_DIR = tempfile.mkdtemp(prefix="cyberrange-v3-eval-")
os.chdir(RUNTIME_DIR)


def record(results: list[tuple[str, bool, str]], name: str, ok: bool, detail: Any = "") -> None:
    results.append((name, bool(ok), str(detail).replace("\n", " ")[:400]))


async def run() -> list[tuple[str, bool, str]]:
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    import app_server
    from shared.auth import get_current_user, UserContext, keycloak_auth
    from shared.config import settings
    from shared.db import init_db
    from shared.schema import NormalizedEvent, SourceType, Severity, Outcome
    from services.ingestion.opensearch_sink import event_sink
    from services.orchestrator.scanner import SafetyScanner

    init_db()
    record(RESULTS, "local profile explicitly configured as simulation", settings.ATTACK_EXECUTION_MODE == "simulation" and settings.DEV_AUTH_ENABLED is False, f"mode={settings.ATTACK_EXECUTION_MODE}; dev_auth={settings.DEV_AUTH_ENABLED}")

    transport = httpx.ASGITransport(app=app_server.app, raise_app_exceptions=False)
    outcomes = RESULTS
    async with httpx.AsyncClient(transport=transport, base_url="http://testclient") as client:
        # Auth must fail closed by default.
        response = await client.get("/api/v1/labs")
        record(outcomes, "unauthenticated protected endpoint denied", response.status_code == 401, response.status_code)
        response = await client.get("/api/v1/labs", headers={"X-Dev-Role": "admin", "X-Dev-Tenant": "00000000-0000-0000-0000-000000000123"})
        record(outcomes, "development role headers ignored when disabled", response.status_code == 401, response.status_code)
        response = await client.get("/api/v1/system/health")
        record(outcomes, "public liveness endpoint responds", response.status_code == 200 and response.json().get("status") == "ok", response.status_code)

        # Explicit local demo auth works only for loopback/TestClient callers.
        settings.DEV_AUTH_ENABLED = True
        response = await client.get("/api/v1/labs", headers={"X-Dev-Role": "admin", "X-Dev-Tenant": "00000000-0000-0000-0000-000000000123"})
        record(outcomes, "local demo identity accepted when explicitly enabled", response.status_code == 200, response.status_code)
        remote_transport = httpx.ASGITransport(app=app_server.app, client=("10.20.30.40", 43210), raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=remote_transport, base_url="http://testclient") as remote_client:
            response = await remote_client.get("/api/v1/labs", headers={"X-Dev-Role": "admin", "X-Dev-Tenant": "00000000-0000-0000-0000-000000000123"})
        record(outcomes, "local demo identity rejected for non-loopback clients", response.status_code == 401, response.status_code)
        settings.DEV_AUTH_ENABLED = False

        # Positive JWT verification with a temporary generated RSA key/JWKS, no external IdP.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        public_jwk.update({"kid": "evaluation-key", "use": "sig", "alg": "RS256"})
        async def fake_jwks(force_refresh: bool = False):
            return {"keys": [public_jwk]}
        original_jwks = keycloak_auth.get_jwks
        keycloak_auth.get_jwks = fake_jwks
        now = int(time.time())
        claims = {
            "iss": keycloak_auth.issuer,
            "aud": settings.KEYCLOAK_JWT_AUDIENCE,
            "sub": "test-user-valid-jwt",
            "preferred_username": "jwt-red-test",
            "iat": now,
            "exp": now + 300,
            "tenant_id": "00000000-0000-0000-0000-000000000123",
            "realm_access": {"roles": ["red"]},
        }
        signed = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "evaluation-key"})
        response = await client.get("/api/v1/labs", headers={"Authorization": f"Bearer {signed}"})
        record(outcomes, "valid signed JWT accepted", response.status_code == 200, response.status_code)
        invalid = jwt.encode({**claims, "iss": "https://untrusted.invalid"}, private_key, algorithm="RS256", headers={"kid": "evaluation-key"})
        response = await client.get("/api/v1/labs", headers={"Authorization": f"Bearer {invalid}"})
        record(outcomes, "JWT with wrong issuer rejected", response.status_code == 401, response.status_code)
        # Invalid bearer tokens must not fall back to development identity.
        response = await client.get("/api/v1/labs", headers={"Authorization": "Bearer invalid.invalid.invalid", "X-Dev-Role": "admin"})
        record(outcomes, "malformed bearer token rejected without fallback", response.status_code == 401, response.status_code)
        keycloak_auth.get_jwks = original_jwks

        # The rest of the flow uses an explicit test identity override so no local dev auth
        # header can mask a missing/invalid JWT in the checks above.
        identity = {"user": UserContext(user_id="44444444-4444-4444-4444-444444444444", username="admin-eval", role="admin", tenant_id="00000000-0000-0000-0000-000000000123")}
        async def override_user():
            return identity["user"]
        app_server.app.dependency_overrides[get_current_user] = override_user

        # Payload-supplied identity must not be able to inject another tenant/session.
        identity["user"] = UserContext(user_id="11111111-1111-1111-1111-111111111111", username="red-eval", role="red", tenant_id="00000000-0000-0000-0000-000000000123")
        spoof_payload = {
            "source_type": "attack", "source_name": "evaluation", "actor": "test",
            "action": "tenant binding spoof test", "tenant_id": "00000000-0000-0000-0000-000000000999",
            "session_id": "sess-foreign-session", "build_id": "bld-foreign-build", "outcome": "simulated"
        }
        response = await client.post("/api/v1/ingest/raw", json={"raw_payload": spoof_payload, "source_hint": "attack"})
        ingest_event = response.json() if response.status_code == 200 else {}
        record(outcomes, "raw event payload cannot spoof tenant/session/build bindings", response.status_code == 200 and ingest_event.get("tenant_id") == identity["user"].tenant_id and ingest_event.get("session_id") is None and ingest_event.get("build_id") is None, f"HTTP {response.status_code}; {str(ingest_event)[:240]}")

        # Lab upload is only a policy check; no image is constructed.
        identity["user"] = UserContext(user_id="44444444-4444-4444-4444-444444444444", username="admin-eval", role="admin", tenant_id="00000000-0000-0000-0000-000000000123")
        dockerfile = b"FROM python:3.12-slim\nUSER 1000\nCMD [\"python\", \"-m\", \"http.server\", \"8080\"]\n"
        response = await client.post("/api/v1/labs", data={"name": "Evaluation lab"}, files={"file": ("Dockerfile", dockerfile, "text/plain")})
        lab_ok = response.status_code == 200 and response.json().get("status") == "policy_checked" and response.json().get("image_tag") is None
        record(outcomes, "Dockerfile upload is policy-checked but not falsely marked built", lab_ok, f"HTTP {response.status_code}; status={response.json().get('status') if response.status_code == 200 else response.text[:140]}")
        lab_id = response.json().get("id") if response.status_code == 200 else None
        if lab_id:
            launch = await client.post(f"/api/v1/labs/{lab_id}/sessions", json={})
            record(outcomes, "unbuilt lab cannot launch", launch.status_code == 409, launch.status_code)
        else:
            record(outcomes, "unbuilt lab cannot launch", False, "lab upload failed")

        compose = "services:\n  app:\n    image: nginx:1.27\n    privileged: true\n"
        response = await client.post("/api/v1/labs", data={"name": "Unsafe compose"}, files={"file": ("docker-compose.yml", compose.encode(), "text/yaml")})
        unsafe_rejected = response.status_code == 200 and response.json().get("status") == "failed" and not response.json().get("safety_scan_result", {}).get("passed", True)
        record(outcomes, "privileged Compose service fails policy check", unsafe_rejected, f"HTTP {response.status_code}; {response.text[:200]}")

        # Create a local simulated session and exercise the central workflow.
        response = await client.post("/api/v1/sessions", json={"target_image": "python:3.12-slim", "ttl_minutes": 30})
        session_ok = response.status_code == 200 and response.json().get("isolation", {}).get("execution_mode") == "simulated"
        record(outcomes, "session creation announces simulation mode", session_ok, f"HTTP {response.status_code}; {response.text[:220]}")
        session_id = response.json().get("session_id") if response.status_code == 200 else None

        if session_id:
            identity["user"] = UserContext(user_id="11111111-1111-1111-1111-111111111111", username="red-eval", role="red", tenant_id="00000000-0000-0000-0000-000000000123")
            response = await client.post("/api/v1/attack/execute", json={"scenario_id": "scn-recon-01", "session_id": session_id})
            attack_data = response.json() if response.status_code == 200 else {}
            record(outcomes, "attack playbook labels simulated work and reports zero live steps", response.status_code == 200 and attack_data.get("execution_mode") == "simulated" and attack_data.get("simulated_steps", 0) > 0 and attack_data.get("live_steps") == 0, f"HTTP {response.status_code}; {str(attack_data)[:240]}")

            identity["user"] = UserContext(user_id="22222222-2222-2222-2222-222222222222", username="blue-eval", role="blue", tenant_id="00000000-0000-0000-0000-000000000123")
            response = await client.post("/api/v1/detection/evaluate", json={"session_id": session_id})
            record(outcomes, "detection rules evaluate current-session events", response.status_code == 200 and "detections_fired" in response.json(), f"HTTP {response.status_code}; {response.text[:220]}")

            test_rule = """title: Evaluation Rule Persistence Check
id: evaluation-rule-persistence
status: test
description: Local test rule for persistence and tenant scoping.
author: CyberRange evaluation
logsource:
  category: application
  product: test
detection:
  selection:
    action|contains:
      - evaluation-rule-trigger
  condition: selection
falsepositives:
  - Evaluation fixture only
level: medium
tags:
  - attack.execution
  - attack.t1059
"""
            response = await client.post("/api/v1/detection/rules", json={"sigma_yaml": test_rule, "tenant_id": "00000000-0000-0000-0000-000000000999"})
            record(outcomes, "non-admin cannot create a rule for another tenant", response.status_code == 403, response.status_code)
            response = await client.post("/api/v1/detection/rules", json={"sigma_yaml": test_rule})
            saved_rule = response.json() if response.status_code == 200 else {}
            record(outcomes, "custom detection rule persists under authenticated tenant", response.status_code == 200 and saved_rule.get("tenant_id") == identity["user"].tenant_id and saved_rule.get("scope") == "tenant", f"HTTP {response.status_code}; {str(saved_rule)[:220]}")
            response = await client.get("/api/v1/detection/rules")
            listed_rules = response.json() if response.status_code == 200 else []
            record(outcomes, "persisted tenant rule is retrievable after commit", response.status_code == 200 and any(r.get("id") == "evaluation-rule-persistence" and r.get("scope") == "tenant" for r in listed_rules), f"HTTP {response.status_code}; rules={len(listed_rules) if isinstance(listed_rules, list) else 'invalid'}")

            response = await client.get(f"/api/v1/validation/coverage?session_id={session_id}")
            cov = response.json() if response.status_code == 200 else {}
            record(outcomes, "simulated events do not count as verified ATT&CK coverage", response.status_code == 200 and cov.get("tested_techniques") == 0 and cov.get("simulated_count", 0) > 0, f"HTTP {response.status_code}; {str(cov)[:260]}")

            response = await client.get(f"/api/v1/scoring/score?session_id={session_id}")
            score_data = response.json() if response.status_code == 200 else {}
            breakdown = score_data.get("breakdown", {})
            record(outcomes, "readiness score disclaims production readiness", response.status_code == 200 and breakdown.get("production_readiness_verified") is False and breakdown.get("ready_for_production") is False, f"HTTP {response.status_code}; {str(breakdown)[:200]}")

            # sessionless events must not leak into session-filtered results
            unscoped_event = NormalizedEvent(
                tenant_id="00000000-0000-0000-0000-000000000123", session_id=None,
                timestamp=datetime.now(timezone.utc), source_type=SourceType.SOC_ACTION,
                source_name="evaluation", actor="test", action="sessionless-sentinel",
                severity=Severity.LOW, outcome=Outcome.SUCCEEDED, raw_payload={"evaluation": True}
            )
            await event_sink.index_event(unscoped_event)
            session_events = event_sink.query_events(tenant_id="00000000-0000-0000-0000-000000000123", session_id=session_id, limit=1000)
            record(outcomes, "session-filtered event query excludes sessionless events", all(e.event_id != unscoped_event.event_id for e in session_events), f"returned={len(session_events)}")

            before = len(event_sink._memory_store)
            event_sink._memory_store.clear()
            restored = event_sink.query_events(tenant_id="00000000-0000-0000-0000-000000000123", session_id=session_id, limit=1000)
            record(outcomes, "events persist outside in-memory cache", len(restored) > 0, f"cached before clear={before}; restored={len(restored)}")

            response = await client.post(f"/api/v1/replay/archive/{session_id}")
            archive = response.json() if response.status_code == 200 else {}
            cap = archive.get("network_capture", {})
            record(outcomes, "missing/empty PCAP is not advertised as captured traffic", response.status_code == 200 and cap.get("status") != "captured" and cap.get("packet_count", 0) == 0, f"HTTP {response.status_code}; {str(cap)[:200]}")
            terminal = archive.get("terminal_recording", {})
            record(outcomes, "simulated terminal transcript is not advertised as a live recording", response.status_code == 200 and terminal.get("status") == "simulated" and terminal.get("source") == "simulated_attack_runner" and terminal.get("execution_mode") == "simulated" and terminal.get("entries", 0) > 0, f"HTTP {response.status_code}; {str(terminal)[:180]}")

            response = await client.get(f"/api/v1/replay/manifest/{session_id}")
            record(outcomes, "same-tenant replay manifest available", response.status_code == 200, response.status_code)

            # AI endpoint should disclose the local canned fallback.
            identity["user"] = UserContext(user_id="33333333-3333-3333-3333-333333333333", username="soc-eval", role="soc", tenant_id="00000000-0000-0000-0000-000000000123")
            response = await client.post("/api/v1/copilot/chat", json={"message": "Summarize this test session", "session_id": session_id, "role": "admin"})
            copilot = response.json() if response.status_code == 200 else {}
            record(outcomes, "Copilot discloses deterministic fallback and non-RAG limitation", response.status_code == 200 and copilot.get("provider_mode") == "local_deterministic_demo_fallback" and "no vector-retrieval RAG" in copilot.get("note", "") and "cannot independently verify live attack execution" in copilot.get("reply", "") and "sensors are currently capturing" not in copilot.get("reply", ""), f"HTTP {response.status_code}; {str(copilot)[:260]}")

            # Another tenant must not access this session or its Copilot context.
            identity["user"] = UserContext(user_id="55555555-5555-5555-5555-555555555555", username="other-blue", role="blue", tenant_id="00000000-0000-0000-0000-000000000999")
            response = await client.get(f"/api/v1/sessions/{session_id}")
            record(outcomes, "cross-tenant session access returns not found", response.status_code == 404, response.status_code)
            response = await client.get(f"/api/v1/replay/manifest/{session_id}")
            record(outcomes, "cross-tenant archive manifest access denied", response.status_code == 404, response.status_code)
            response = await client.post("/api/v1/copilot/chat", json={"message": "Summarize", "session_id": session_id, "role": "admin"})
            record(outcomes, "Copilot cannot access cross-tenant context or trust supplied role", response.status_code == 404, response.status_code)
            response = await client.post("/api/v1/attack/execute", json={"scenario_id": "scn-recon-01", "session_id": session_id})
            record(outcomes, "non-Red role cannot launch an attack", response.status_code == 403, response.status_code)

            identity["user"] = UserContext(user_id="33333333-3333-3333-3333-333333333333", username="soc-eval", role="soc", tenant_id="00000000-0000-0000-0000-000000000123")
            response = await client.post("/api/v1/ci-gate/webhook", json={"dockerfile_content": "FROM python:3.12-slim"})
            record(outcomes, "CI gate refuses unbuilt Dockerfile input", response.status_code == 409, f"HTTP {response.status_code}; {response.text[:160]}")

            # Valid image-reference request should fail closed as INCONCLUSIVE in local
            # simulation, rather than crash on unresolved FastAPI Depends defaults or PASS.
            response = await client.post("/api/v1/ci-gate/webhook", json={"image_tag": "python:3.12-slim", "min_score_threshold": 0})
            ci_data = response.json() if response.status_code == 200 else {}
            record(outcomes, "CI gate local simulation returns explicit INCONCLUSIVE result", response.status_code == 200 and ci_data.get("gate_result") == "INCONCLUSIVE" and ci_data.get("live_steps") == 0 and ci_data.get("execution_mode") in {"simulated", "mixed"}, f"HTTP {response.status_code}; {str(ci_data)[:260]}")
            build_rows = (await client.get("/api/v1/ci-gate/builds")).json()
            record(outcomes, "CI gate report persists and is retrievable", response.status_code == 200 and any(row.get("build_id") == ci_data.get("build_id") for row in build_rows), f"saved={any(row.get('build_id') == ci_data.get('build_id') for row in build_rows)}; rows={len(build_rows) if isinstance(build_rows, list) else 'not-list'}")

            # Demo loop must report actual counts based on per-step results.
            identity["user"] = UserContext(user_id="44444444-4444-4444-4444-444444444444", username="admin-eval", role="admin", tenant_id="00000000-0000-0000-0000-000000000123")
            response = await client.post("/api/v1/system/demo-seed")
            demo = response.json() if response.status_code == 200 else {}
            record(outcomes, "quick demo reports actual simulated/live counts", response.status_code == 200 and demo.get("execution_mode") in {"simulated", "mixed"} and demo.get("attacks_executed_live") == 0 and demo.get("simulated_steps", 0) > 0, f"HTTP {response.status_code}; {str(demo)[:260]}")
        else:
            record(outcomes, "core session workflow continued", False, "session creation failed")

        # Scanner must not invent CVEs when Trivy is unavailable or the command fails.
        scan = SafetyScanner.scan_image("this-image-must-not-have-synthetic-findings:local")
        record(outcomes, "image scanner does not fabricate findings", scan.get("verified") is True or scan.get("findings", []) == [], f"mode={scan.get('mode')}; verified={scan.get('verified')}; findings={len(scan.get('findings', []))}")

        app_server.app.dependency_overrides.clear()

    return outcomes


RESULTS: list[tuple[str, bool, str]] = []


def main() -> int:
    try:
        outcomes = asyncio.run(run())
    except Exception as exc:
        import traceback
        traceback.print_exc()
        print(f"EVALUATION ERROR: {type(exc).__name__}: {exc}")
        return 2

    print(f"Local evaluation runtime (temporary): {RUNTIME_DIR}")
    for name, passed, detail in outcomes:
        print(f"{'PASS' if passed else 'FAIL'}\t{name}\t{detail}")
    passed_count = sum(1 for _, passed, _ in outcomes if passed)
    failed_count = len(outcomes) - passed_count
    print(f"SUMMARY\t{passed_count}/{len(outcomes)} passed; {failed_count} failed")
    print("SCOPE\tLocal simulation and security-behavior checks only; external/live infrastructure is not verified.")
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
