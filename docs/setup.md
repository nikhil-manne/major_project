# Setup Guide: Local Simulation Profile

## Important boundary

These steps are for a **local development/simulation profile**. They do not configure a production cyber range and do not prove that Kubernetes, Keycloak, PostgreSQL, Kafka, OpenSearch, MinIO, live sensors, or real attacks work.

## Prerequisites

- Python 3.11 or a compatible version supported by `requirements.txt`.
- Node.js and npm versions compatible with `web/package-lock.json`.
- A terminal opened at the project root.
- Optional Docker Engine/Desktop for separate container workflows.

## 1. Protect configuration first

1. Inspect `.env.example` for required variables.
2. Copy `.env.example` to `.env` for local use.
3. Replace default admin credentials and any signing secret before running the app.
4. Never include a real `.env` file in a distributable ZIP or Git commit.
5. Keep the API bound to loopback for local-only use.

PowerShell:

```powershell
Copy-Item .env.example .env
```

Do not assume sample credentials are safe. If a real secret was included in a shared archive or repository, rotate it.

## 2. Create a Python environment and install dependencies

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app_server.py
```

The supplied project documentation indicates the local API is expected at `http://127.0.0.1:8000`, with interactive API documentation at `/docs`. Confirm the actual startup log rather than assuming the port if configuration changes it.

## 3. Install and run the frontend

Open a second terminal:

```powershell
cd web
npm ci
npm run dev -- --host 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000` in a browser.

To test production bundling:

```powershell
npm run build
```

The supplied evaluation could not complete the production build in its review environment. A clean successful build remains a required verification item.

## 4. Run local evaluation

From the project root, with the required Python dependencies installed:

```powershell
python scripts/evaluate_local.py
```

The supplied report says `scripts/test_integration.py` delegates to the same local evaluation suite, so it is not an independent test suite. Read the individual result lines and record any failures.

## 5. Optional external services

The repository contains configuration for PostgreSQL, Kafka, OpenSearch, Keycloak, MinIO, and Kubernetes. Start and configure these only when verifying the corresponding integration. A running container is not sufficient; run an application-level test that proves the service is actually used.

The supplied local evaluation used SQLite/local-disk fallbacks because some dependencies were unavailable. That is a local-development fallback, not proof of the external integrations.

## 6. Troubleshooting principles

- If Python dependency installation fails, capture the full error and interpreter version.
- If `npm ci` fails, do not copy `node_modules` from another OS or architecture; use the lockfile and a clean install.
- If an external service is unavailable, record the dependent feature as `INTEGRATION UNVERIFIED` rather than silently treating fallback output as a live result.
- A server starting successfully proves only that it started; it does not prove every integration works.

## 7. Safe shutdown

Stop the backend and frontend with `Ctrl+C`. Stop any optional containers with the appropriate Docker Compose command only after confirming which services and volumes are in use. Avoid deleting persistent volumes unless you intend to remove local test data.
