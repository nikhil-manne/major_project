# Architecture

This document describes the system's components and how they connect. For what each tool is and why it was chosen, see `requirements.md`. For the build order, see `plan.md`.

---

## High-Level Layout

```
                         ┌─────────────────────────┐
                         │        Keycloak          │  (Auth/RBAC)
                         └─────────────┬─────────────┘
                                        │ JWT (role, tenant)
                 ┌──────────────────────┼──────────────────────┐
                 │                      │                      │
         ┌───────▼───────┐    ┌─────────▼────────┐    ┌────────▼───────┐
         │ Red Team       │    │ Blue Team         │    │ SOC Dashboard   │
         │ Dashboard      │    │ Dashboard         │    │                 │
         └───────┬────────┘    └─────────┬─────────┘    └────────┬────────┘
                 │                       │                       │
                 └───────────────┬───────┴───────────────┬───────┘
                                  │                       │
                          ┌───────▼───────┐       ┌───────▼────────┐
                          │ Copilot Service│       │ Admin Dashboard │
                          │ (FastAPI + RAG)│       │ (tenant mgmt,   │
                          └───────┬────────┘       │ scenario builder)│
                                  │                └────────┬────────┘
                                  │                         │
            ┌─────────────────────┼─────────────────────────┘
            │                     │
     ┌──────▼──────┐      ┌───────▼───────┐
     │ OpenSearch   │◄─────┤ Validation /   │
     │ (events, logs)│      │ Scoring Engine │
     └──────▲───────┘      └────────────────┘
            │
            │ normalized events
     ┌──────┴────────────────────────────────────────┐
     │                  Apache Kafka                  │
     │  topics: raw.attack, raw.network, raw.host,     │
     │          raw.soc, normalized.events             │
     └──────┬─────────────┬─────────────┬─────────────┘
            │             │             │
    ┌───────▼─────┐ ┌─────▼──────┐ ┌────▼─────────┐
    │ Attack Engine│ │ Detection   │ │ Ingestion/   │
    │ (red team    │ │ Engine      │ │ Normalizer    │
    │ scenarios)   │ │ (Sigma/     │ │ Workers       │
    │              │ │ pySigma)    │ │               │
    └───────┬──────┘ └─────┬──────┘ └───────────────┘
            │              │
     ┌──────▼──────────────▼──────┐
     │   Sandbox Orchestrator       │
     │   (Kubernetes namespace per  │
     │   session, NetworkPolicy)    │
     └──────┬────────────────────┬─┘
            │                    │
   ┌────────▼────────┐  ┌────────▼─────────┐
   │ Red Team Toolbox  │  │ Target Container  │
   │ Pod (ttyd/        │  │ (user-uploaded    │
   │ Metasploit/Nmap)  │  │  Docker build)     │
   └────────┬──────────┘  └────────┬──────────┘
            │                      │
            │     ┌────────────────▼────────┐
            │     │ Sensors (sidecars):       │
            └─────► Falco (host) + Suricata   │
                  │ (network)                  │
                  └─────────────┬──────────────┘
                                │
                        ┌───────▼────────┐
                        │ Replay Engine   │
                        │ (reads archived │
                        │ sessions, re-   │
                        │ emits events)   │
                        └───────┬────────┘
                                │
                        ┌───────▼────────┐
                        │ MinIO (archived │
                        │ .cast, .pcap,   │
                        │ event batches)  │
                        └────────────────┘
```

---

## Components

### 1. Identity Layer
- **Keycloak** issues JWTs carrying `role` (red/blue/soc/admin) and `tenant_id`.
- Every service downstream checks this JWT before returning data — this is what enforces multi-tenancy at the data layer, not just the UI.

### 2. Sandbox Orchestrator
- Owns the lifecycle of a "session": create namespace → apply NetworkPolicy → deploy target + toolbox + sensors → monitor TTL → destroy + archive.
- Exposed as an internal API (`POST /sessions`, `DELETE /sessions/{id}`) called by the CI/CD webhook (pre-release mode) or manually from the Admin Dashboard.

### 3. Attack Engine
- Runs YAML-defined scenarios (one scenario = ordered steps, each mapped to a MITRE technique) against the sandboxed target.
- Also accepts manual red-team terminal input (via the toolbox pod) as an alternate attack source.
- Emits one event per attack step into `raw.attack`.

### 4. Sensors + Detection Engine
- **Falco** and **Suricata** run as sidecars inside the same session namespace, watching the target container.
- Their output is forwarded (via Fluent Bit) into `raw.host` / `raw.network`.
- The **Detection Engine** continuously runs compiled Sigma rules against normalized events in OpenSearch; a match emits a `detection` event, tagged with the same `mitre_technique` and `session_id` where traceable.

### 5. Ingestion / Normalizer
- Kafka consumers subscribed to all `raw.*` topics, transforming each source's native format into the shared normalized event schema (see `schema.md`), writing to `normalized.events` → sinked into OpenSearch.

### 6. Validation Engine
- Reads `normalized.events` grouped by `session_id` + `mitre_technique`.
- Cross-references against the MITRE ATT&CK reference table (loaded from STIX data) to compute covered / gap / untested per technique.

### 7. Scoring Engine
- Reads validation output + incident resolution data to compute the Security Readiness Score per session/build.

### 8. Replay Engine
- Pulls an archived session's `.cast`, `.pcap`, and event batch from MinIO.
- Re-emits events onto `raw.attack` (timestamp-shifted, flagged `replay: true`) and replays `.pcap` via `tcpreplay`, so a *new* detection rule can be tested against a *past* attack.

### 9. Copilot Service
- Single FastAPI service, one codepath, role-aware system prompts.
- RAG retrieval step is **scoped by the caller's JWT** (`tenant_id`, and `session_id` if provided) before querying OpenSearch — this is the enforcement point for "a red teamer's copilot can't see blue team's internal notes," etc.
- Any Sigma rule the copilot generates is validated with `pySigma` before being returned to the user.

### 10. Dashboards
- Three role-specific React apps (Red, Blue, SOC) + one Admin app, each calling the backend services above through a shared API gateway (or directly, for project scope — a gateway is a nice-to-have, not required to prove the concept).

---

## Data Flow Summary (one attack, start to finish)
1. Red team runs an attack step (manual or scripted) → event → `raw.attack`.
2. Falco/Suricata observe the resulting system/network behavior → events → `raw.host`/`raw.network`.
3. Ingestion normalizes all three → `normalized.events` → OpenSearch.
4. Detection Engine's Sigma rules match against the Falco/Suricata events → emits a `detection` event if caught.
5. Validation Engine joins the `attack` event and `detection` event by `mitre_technique` + `session_id` + time window → marks that technique "covered" or "gap."
6. Scoring Engine aggregates all techniques in the session → Security Readiness Score.
7. Copilot Service can be asked, at any point, to explain what just happened using the same data.
8. On session teardown, everything is archived to MinIO, replayable later by the Replay Engine.

---

## Two Deployment Topologies

**Pre-release mode:** Orchestrator creates a namespace per build, attack engine runs scripted scenarios automatically (no manual red teamer required), session is short-lived (minutes to a couple hours), result is a pass/fail build report.

**Production mode:** No sandbox orchestration, no attack engine. Production log forwarders (syslog/CloudTrail/Falco-on-prod-hosts) feed directly into `raw.host`/`raw.network`, and only the Detection Engine, Validation Engine (read-only historical coverage), and SOC Dashboard + Copilot are active. This reuses the exact same Detection Engine and event schema as pre-release mode — no separate codebase.
