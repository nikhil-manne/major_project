# Unified AI-Powered Cyber Range & Security Validation Platform

**Project status: active development.** This repository contains a multi-module cybersecurity platform prototype. The long-term goal is to connect controlled attack emulation, event collection, detection, MITRE ATT&CK validation, replay, heuristic scoring, SOC workflows, a Copilot, and CI security gates. Not every listed subsystem is integrated or validated yet.

## What works in local simulation mode

The backend and frontend can be developed locally without a Kubernetes cluster. Local runs explicitly label attack results as **simulated**, save normalized events to a relational database fallback, exercise rule-based detection, produce a limited test-coverage report, and expose replay/archive metadata. Simulated events are not counted as verified live attack coverage. The source includes tests for authorization defaults, tenant boundaries, unbuilt-lab handling, simulation labels, persistence fallback, and score disclaimers.


## Sandbox evaluation report

See [`docs/evaluation-report-sandbox.md`](docs/evaluation-report-sandbox.md) for the fixes applied and the exact local checks executed during this review. That report distinguishes simulated local workflows from functionality that still requires a real browser build, Kubernetes cluster, Keycloak, PostgreSQL, Kafka, OpenSearch, MinIO, Trivy, packet capture, and live attack tests.

## Feature maturity guide

| Capability | Current status in this revision | Evidence / limitation |
|---|---|---|
| React dashboard and FastAPI routes | Implemented; frontend build still needs a clean local verification | UI source and API routers are present |
| Auth/RBAC | Password login, signed local bearer tokens, admin-managed users and role checks are integrated; live Keycloak SSO remains separate and unverified | Local bootstrap credentials are environment-configured; rotate the example credentials and signing secret before shared deployment |
| Labs file upload/policy checks | Implemented as policy-check stage | An uploaded Dockerfile is **not built** into an image by this endpoint |
| Kubernetes sandbox | Integration code present, not verified against a live cluster here | Local evaluation runs simulation mode; cluster setup and image pull permissions are still needed |
| Attack playbooks | Implemented with explicit simulated/live outcomes | Live execution requires a working, hardened sandbox and approved test assets |
| Event persistence | Relational persistence path implemented; SQLite fallback evaluated | PostgreSQL/Kafka/OpenSearch integration was not available in the local evaluation environment |
| Detection and validation | Rule evaluation runs in local simulation tests | Simulated events do not qualify as proven live coverage; rule precision needs more scenario testing |
| Replay / network capture | Event archive and replay metadata implemented | A real PCAP is only reported when a valid capture with packets is retrieved; empty placeholder files are not presented as captures |
| Scanner | Real Trivy/Hadolint calls where installed; fallback checks are labelled unverified | No fake CVEs should be reported as an image scan result |
| Readiness score | Heuristic is computed and explicitly not a production certification | Do not interpret it as a certified security or release-safety rating |
| AI Copilot | Provider call is optional; deterministic local fallback is not a language model | Provider availability and output quality must be independently tested; suggestions do not execute actions |
| CI gate | Policy workflow is present; live release-gate verification is incomplete | An uploaded Dockerfile is rejected until a trusted build pipeline produces an image |

## Architecture target

The intended deployment can use Keycloak, PostgreSQL, Kafka, OpenSearch, MinIO, and Kubernetes. These services are not all required for the local simulation profile and their presence in `docker-compose.yml` does not itself establish that the application is integrated with or validated against them.

## Local development (simulation mode)

### Prerequisites

- Python 3.11+
- Node.js and npm (use the versions compatible with `web/package-lock.json`)
- Optional: Docker Desktop/Engine for local target applications

### 1. Configure the backend

Copy `.env.example` to `.env`. Sign into the local web UI using `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD`; do not enable `DEV_AUTH_ENABLED` for normal use. The API launcher binds to `127.0.0.1` by default. The local username/password flow is suitable for local testing only; for an Internet-facing deployment, configure a unique strong `AUTH_SECRET_KEY`, change the bootstrap admin password, enable HTTPS, and review the security model before deployment. Keycloak SSO support remains available for verified Keycloak bearer tokens but is not the login flow used by this local page.

Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app_server.py
```

The API is at `http://127.0.0.1:8000`; OpenAPI docs are at `http://127.0.0.1:8000/docs`.

### 2. Configure the frontend

In another terminal:

```powershell
cd web
npm ci
npm run dev -- --host 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000`. If a clean `npm ci` or `npm run build` fails, record the error; a pre-packed `node_modules` folder from another operating system is not a reliable install.

### 3. Run the local evaluation suite

```powershell
python scripts/evaluate_local.py
```

This test uses temporary local storage and explicit simulated execution. It checks the workflows and security properties that can run without external infrastructure. A passing local suite does **not** prove Kubernetes, Keycloak, Kafka, OpenSearch, MinIO, actual packet capture, live attack execution, or the production frontend build are working.

`scripts/test_integration.py` is now a compatibility entry point to the same local evaluation suite. Use `scripts/evaluate_local.py` and inspect each check result; neither script verifies external/live infrastructure.

## Live infrastructure verification checklist

Do not call the full platform end-to-end verified until you have independently tested:

1. Keycloak-issued JWTs with expected issuer, audience, role, and tenant claims.
2. PostgreSQL persistence and migrations across restarts.
3. Kafka producer and consumer integration with event correlation.
4. OpenSearch indexing, query filtering, and index mappings.
5. MinIO upload/download and archive integrity.
6. A hardened Kubernetes cluster with the required NetworkPolicies, Pod Security settings, quotas, service accounts, image provenance and cleanup.
7. An isolated image-builder workflow. The current upload path does not build arbitrary uploaded Dockerfiles.
8. Real sensor/event ingestion and reliable attack-to-detection correlation.
9. A captured PCAP with packet records, and replay behavior validated against that capture.
10. CI gate results that only pass on explicitly configured, live, verified tests and policy conditions.

## Security boundary

Test only against an isolated training target or another environment for which you have explicit permission. Never enable local demo identity switching on a network-accessible deployment. Do not deploy untrusted uploaded images in a shared Kubernetes cluster without a hardened sandbox boundary and review of the runtime policy.

## API reference

Interactive endpoint documentation is available at `/docs` while the backend is running. The route definitions are in `app_server.py` and the modules under `services/`.

## Contribution and reporting rule

Use four status labels in issues, reports, and presentations:

- **Designed** — described in architecture/docs.
- **Implemented** — code exists.
- **Integrated** — components exchange real data successfully.
- **Verified** — repeatable tests demonstrate the claimed behavior.

Do not label a feature `DONE` solely because its UI, route, or service module exists.

## Windows launcher troubleshooting

Use `run.bat` from the extracted project root. The launcher keeps its window open on setup errors and writes startup notes to `logs\launcher.log`. Backend and frontend run in separate persistent command windows so their tracebacks remain visible. If startup fails, copy the error from the window and inspect the log; a successful launcher run does not prove all optional services are healthy.


## Login and user management

The web dashboard starts with a login page. The bootstrap administrator is provisioned from `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD` in `.env`. For a fresh local-only demo, the `.env.example` defaults are `admin` / `CyberRangeAdmin2026#`; change them before starting the app if the project is used by anyone else. On startup the app creates or refreshes the bootstrap administrator credential from these environment-backed settings.

After signing in as an administrator, open **Users** to create accounts and assign one of these roles: **Administrator**, **Red Team**, **Blue Team**, or **SOC Analyst**. New accounts are limited to the signed-in administrator's tenant; usernames must be unique across the installation because sign-in uses a username. Passwords are stored as salted PBKDF2 hashes, and protected API calls use a signed bearer token. Set a unique, long `AUTH_SECRET_KEY` and a strong admin password in `.env` before any non-local deployment. Do not expose the demo service directly to the Internet.

`401 Unauthorized` on a protected API is expected before login; after login, the frontend supplies the bearer token automatically. Kafka messages about `localhost:9092` mean the optional Kafka service is not reachable; they are separate from login and do not themselves cause the API 401 responses.
