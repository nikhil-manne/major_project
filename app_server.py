"""
Cyber Range & Security Validation Platform - Unified Gateway Server
Integrates all services, real PostgreSQL database, Kafka event backbone,
Kubernetes orchestration, MinIO object storage, and Labs into a single high-performance API server.
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
from typing import Any, Dict
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from shared.config import settings
from shared.auth import get_current_user, require_roles, UserContext
from shared.db import init_db, SessionLocal
from shared.auth_routes import router as auth_router, ensure_initial_admin
from shared.s3_client import s3_client
from shared.kafka_client import kafka_producer
from services.orchestrator.k8s_client import k8s_client
from services.ingestion import ingestion_router, events_router, event_sink
from services.ingestion.normalizer import normalizer_worker
from services.orchestrator import orchestrator_router
from services.attack_engine import attack_router
from services.detection_engine import detection_router
from services.detection_engine.service import detection_worker
from services.replay_engine import replay_router
from services.validation_engine import validation_router
from services.scoring_engine import scoring_router
from services.copilot import copilot_router
from services.ci_gate import ci_gate_router
from services.labs import labs_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize PostgreSQL Database & Seed records
    try:
        init_db()
        ensure_initial_admin()
        print("[Startup Info] Login enabled. Bootstrap admin account is loaded from INITIAL_ADMIN_USERNAME / INITIAL_ADMIN_PASSWORD.")
    except Exception as e:
        print(f"[Startup Warning] Database/authentication initialization: {e}")

    # 2. Start consumers only when Kafka is available. Local mode remains explicit.
    try:
        if kafka_producer._connected:
            normalizer_worker.start()
            detection_worker.start()
        else:
            print("[Startup Info] Kafka is unavailable; background consumers were not started. Events use the configured fallback sink.")
    except Exception as e:
        print(f"[Startup Warning] Kafka background workers: {e}")

    yield

    # Cleanup on shutdown
    normalizer_worker.stop()
    detection_worker.stop()


app = FastAPI(
    title=settings.APP_NAME,
    description="Unified AI-Powered Cyber Range & Security Validation Platform API with Dockerfile Uploads & Multi-Lab Support",
    version="2.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public login endpoint and authenticated identity/user-management endpoints
app.include_router(auth_router)

# Mount all service routers
app.include_router(labs_router, dependencies=[Depends(get_current_user)])
app.include_router(ingestion_router, dependencies=[Depends(get_current_user)])
app.include_router(events_router, dependencies=[Depends(get_current_user)])
app.include_router(orchestrator_router, dependencies=[Depends(get_current_user)])
app.include_router(attack_router, dependencies=[Depends(get_current_user)])
app.include_router(detection_router, dependencies=[Depends(get_current_user)])
app.include_router(replay_router, dependencies=[Depends(get_current_user)])
app.include_router(validation_router, dependencies=[Depends(get_current_user)])
app.include_router(scoring_router, dependencies=[Depends(get_current_user)])
app.include_router(copilot_router, dependencies=[Depends(get_current_user)])
app.include_router(ci_gate_router, dependencies=[Depends(get_current_user)])


@app.get("/api/v1/system/health")
async def system_health():
    """Public, minimal liveness endpoint; detailed infrastructure state is not disclosed."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app": settings.APP_NAME,
        "execution_mode": settings.ATTACK_EXECUTION_MODE,
    }


@app.post("/api/v1/system/demo-seed", dependencies=[Depends(require_roles(["admin"]))])
async def seed_demo_data():
    """
    Seeds a complete, end-to-end demo session with attacks, detections,
    MITRE coverage, and readiness score ready for immediate review!
    """
    from services.orchestrator.service import CreateSessionRequest, create_session
    from services.attack_engine.runner import AttackScenarioRunner
    from services.detection_engine.service import EvaluateRequest, evaluate_detection_rules
    from services.scoring_engine.service import calculate_readiness_score
    from services.replay_engine.archiver import SessionArchiver
    from shared.auth import UserContext

    sys_user = UserContext(
        user_id="usr-admin-4444",
        username="admin1",
        role="admin",
        tenant_id="00000000-0000-0000-0000-000000000123"
    )

    with SessionLocal() as db:
        # 1. Create Demo Session
        s_req = CreateSessionRequest(
            tenant_id="00000000-0000-0000-0000-000000000123",
            # This demo session has no verified build artifact; it is intentionally
            # independent of the lab upload/build workflow and runs in the configured mode.
            lab_id=None,
            target_image="python:3.12-slim",
            build_id=None,
            ttl_minutes=45
        )
        session = await create_session(s_req, db=db, user=sys_user)
        sid = session.session_id

        # 2. Run T1046 Recon scenario
        run1 = await AttackScenarioRunner.execute_scenario(
            scenario_id="scn-recon-01",
            session_id=sid,
            tenant_id="00000000-0000-0000-0000-000000000123",
            build_id=None,
            operator="red1"
        )

        # 3. Run T1210 SMB exploit scenario
        run2 = await AttackScenarioRunner.execute_scenario(
            scenario_id="scn-smb-02",
            session_id=sid,
            tenant_id="00000000-0000-0000-0000-000000000123",
            build_id=None,
            operator="red1"
        )

        # 4. Run T1059 Command execution
        run3 = await AttackScenarioRunner.execute_scenario(
            scenario_id="scn-sh-03",
            session_id=sid,
            tenant_id="00000000-0000-0000-0000-000000000123",
            build_id=None,
            operator="red1"
        )

        # 5. Evaluate detections
        eval_res = await evaluate_detection_rules(
            EvaluateRequest(session_id=sid, tenant_id="00000000-0000-0000-0000-000000000123"),
            user=sys_user
        )

        # 6. Archive session to MinIO
        archive = SessionArchiver.archive_session(
            session_id=sid,
            tenant_id="00000000-0000-0000-0000-000000000123"
        )

        # 7. Compute readiness
        score = await calculate_readiness_score(
            tenant_id="00000000-0000-0000-0000-000000000123",
            session_id=sid,
            build_id=None,
            db=db,
            user=sys_user
        )

        runs = [run1, run2, run3]
        live_steps = sum(run.get("live_steps", 0) for run in runs)
        simulated_steps = sum(run.get("simulated_steps", 0) for run in runs)
        blocked_steps = sum(run.get("blocked_steps", 0) for run in runs)
        execution_modes = {run.get("execution_mode", "unknown") for run in runs}
        actual_mode = execution_modes.pop() if len(execution_modes) == 1 else "mixed"

        return {
            "status": "demo_environment_seeded",
            "session_id": sid,
            "scenarios_submitted": len(runs),
            "execution_mode": actual_mode,
            "attacks_executed_live": live_steps,
            "simulated_steps": simulated_steps,
            "blocked_steps": blocked_steps,
            "detections_fired": eval_res.get("detections_fired", 0),
            "readiness_score": score.score,
            "coverage_percentage": score.coverage_pct,
            "score_interpretation": "prototype heuristic; not a production security certification"
        }


# Static build mount for frontend web application
dist_dir = os.path.join(os.path.dirname(__file__), "web", "dist")
assets_dir = os.path.join(dist_dir, "assets")

if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serves index.html for root and client-side SPA routes while preserving API paths."""
    from fastapi.responses import FileResponse
    index_file = os.path.join(dist_dir, "index.html")
    if os.path.exists(index_file):
        target_path = os.path.join(dist_dir, full_path)
        if full_path and os.path.isfile(target_path):
            return FileResponse(target_path)
        return FileResponse(index_file)
    return JSONResponse({"status": "Cyber Range Backend API Operational", "api_docs": "/docs"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app_server:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
