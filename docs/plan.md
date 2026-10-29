# Project Plan

This document explains **what we are building** and **how we are building it**, broken into phases. Each phase produces a working, demoable increment — by the end of every phase, something real runs end-to-end, not just a mockup.

Reference: see `goal.md` for the full vision and `requirements.md` for the tools used below.

---

## What We Are Building (Recap)

A unified platform where Red Team, Blue Team, and SOC share one engine and one data model to **attack, defend, analyze, replay, validate, and report** on the security of a software build — in a pre-release sandbox and later in production — with an AI Copilot assisting all three roles.

The platform is built as independent microservices that all read/write to **one shared, normalized event schema**, which is what makes replay and validation possible without manual stitching.

---

## How We Are Building It (Phased Approach)

---

### Phase 0 — Foundations & Environment Setup
**Goal:** Get the core infrastructure running locally before any feature code is written.

- Set up **k3s/minikube** as the Kubernetes environment.
- Stand up **Kafka**, **PostgreSQL**, and **OpenSearch** as the shared backbone (via Docker Compose for local dev).
- Set up **Keycloak** with three roles: Red Team, Blue Team, SOC (Admin added later).
- Design and finalize the **normalized event schema** (the JSON shape every event in the system will follow — attack, detection, network, host, SOC action).
- Initialize the Git repo structure (one service per folder, as listed in `requirements.md`).

**Deliverable:** Empty but running platform skeleton — login works, infra is up, schema is documented.

---

### Phase 1 — Ingestion Pipeline & Data Plane
**Goal:** Prove that raw security data can flow into the system and come out normalized.

- Build the **ingestion-service**: Kafka consumers that take raw log formats (dummy data first) and convert them into the normalized schema.
- Wire normalized events into OpenSearch for storage/search.
- Build a minimal **admin dashboard** page that just shows a live feed of normalized events, to visually confirm the pipeline works.

**Deliverable:** Dummy security events flow in, get normalized, and are visible in a dashboard.

---

### Phase 2 — Sandbox Orchestration
**Goal:** Automatically create and destroy an isolated environment per session.

- Build the **orchestrator service**: given a `session_id` and a target Docker image, it creates a Kubernetes namespace, applies NetworkPolicy isolation, deploys the target container.
- Add image safety checks before deployment: **Trivy** + **Hadolint** scan the uploaded Dockerfile/image first.
- Add automatic teardown via a TTL-based scheduler.

**Deliverable:** Upload a Dockerfile → a real, isolated sandbox spins up and later tears itself down automatically.

---

### Phase 3 — Red Team Access & Attack Engine
**Goal:** Let a red team user actually attack the sandboxed target, and record every action.

- Deploy a **red team toolbox pod** (Nmap, Metasploit, sqlmap) per session, exposed via **ttyd** in the browser, scoped to that session's network only.
- Wrap the terminal with **asciinema** to record every keystroke/output.
- Build 3–5 **scripted attack scenarios** (YAML definitions mapped to MITRE ATT&CK techniques) that can also be run automatically, not just manually.
- Every attack action (manual or scripted) emits a structured event into the `raw.attack` Kafka topic.

**Deliverable:** A red team user can log in, get a terminal, attack the sandboxed target, and every action is both visible live and recorded for later replay.

---

### Phase 4 — Blue Team Detection Engine
**Goal:** Catch what red team is doing, in real time.

- Deploy **Falco** (host/runtime) and **Suricata** (network) as sidecars in each session's namespace.
- Build the **detection-engine service**: store Sigma rules in PostgreSQL, compile them with **pySigma** into OpenSearch queries, run them continuously against incoming events.
- Build the **Blue Team dashboard**: live alert feed, and the ability to write/edit a Sigma rule and see it start catching activity immediately.

**Deliverable:** Blue team can watch red team's attack unfold as live alerts, and test new detection rules against it in real time.

---

### Phase 5 — Recording, Archival & Replay
**Goal:** Make every session fully reproducible after the fact.

- Add **tcpdump** capture alongside the asciinema terminal recording, both tagged with `session_id`.
- On session teardown, archive terminal `.cast`, network `.pcap`, and the full event timeline to **MinIO**.
- Build the **replay-engine service**: re-emits a past session's events on a synchronized timeline, and uses **tcpreplay** to re-inject the original traffic.
- Build a **replay UI**: timeline scrubber showing terminal playback, network activity, and alerts side by side.

**Deliverable:** Any past session can be replayed end-to-end — proving the "record everything, replay anytime" promise from the goal.

---

### Phase 6 — Validation Engine (MITRE ATT&CK Coverage)
**Goal:** Turn attack + detection data into an automatic coverage report.

- Load the **MITRE ATT&CK STIX data** into PostgreSQL as the technique reference table.
- Build the **validation-engine service**: for each technique, check whether an attack event and a matching detection event both exist within a time window → covered / gap / untested.
- Render results using the **MITRE ATT&CK Navigator** layer format as a heatmap in the dashboard.

**Deliverable:** A live, auto-generated MITRE coverage heatmap — no manual spreadsheet mapping.

---

### Phase 7 — Scoring Engine & SOC Dashboard
**Goal:** Give leadership and SOC analysts a single number and a working triage view.

- Build the **scoring-engine**: compute the weighted Security Readiness Score (coverage %, detection latency, resolved incidents) per session/build.
- Build the full **SOC dashboard**: case management, alert triage view, basic threat-hunting query interface over OpenSearch.

**Deliverable:** A readiness score is generated per test session, and SOC has a working analyst workspace.

---

### Phase 8 — AI Security Copilot
**Goal:** Add the assistant layer across all three roles.

- Build the **copilot-service** (FastAPI + RAG over OpenSearch, scoped by role and tenant/session).
- Feature 1 (Blue Team): explain a selected alert in plain language + suggest a MITRE technique it maps to.
- Feature 2 (Blue Team): given a detection gap, generate a draft Sigma rule (validated by `pySigma` before shown to the user).
- Feature 3 (Red Team): given current recon output, suggest a plausible next attack technique.
- Feature 4 (SOC): summarize a session/incident timeline into a short written report.

**Deliverable:** All three dashboards have a working "Ask Copilot" feature grounded in real session data.

---

### Phase 9 — Pre-Release Gate Integration (CI/CD Mode)
**Goal:** Prove the platform works as an automated security gate, not just a manual range.

- Build a webhook endpoint that a CI pipeline (GitHub Actions) calls with a new build.
- Wire it to automatically trigger Phase 2's orchestrator → Phase 3's scripted attack scenarios (not manual red team) → Phase 4's detection → Phase 6's scoring.
- Output a pass/fail **build security report**, demonstrating the "shift-left" pre-release testing mode from `goal.md`.

**Deliverable:** A simulated CI pipeline run that automatically tests a new build's security and produces a report — no human in the loop.

---

### Phase 10 — Final Integration, Polish & Demo Prep
**Goal:** Tie every phase together into one coherent, reviewable system.

- End-to-end run-through: upload build → sandbox → attack → detect → validate → score → replay → copilot explanation — all in one continuous demo.
- Fix cross-service rough edges, add basic error handling/loading states to dashboards.
- Prepare the final report: architecture diagrams, MITRE coverage screenshots, readiness score trend, replay demo recording.

**Deliverable:** The complete working platform, ready for final review/demo.

---

## Phase Summary Table

| Phase | Focus | Key Deliverable |
|---|---|---|
| 0 | Foundations | Infra running, schema defined |
| 1 | Data plane | Events flow in and normalize |
| 2 | Sandbox orchestration | Isolated environment per session |
| 3 | Red team | Attacks executed and recorded |
| 4 | Blue team | Attacks detected in real time |
| 5 | Recording & replay | Full sessions replayable |
| 6 | Validation | Automatic MITRE coverage heatmap |
| 7 | Scoring & SOC | Readiness score + analyst dashboard |
| 8 | AI Copilot | Role-aware assistant live in all dashboards |
| 9 | CI/CD gate | Automated pre-release security testing |
| 10 | Integration | Full end-to-end demo-ready system |

---

## Notes on Sequencing
- Phases 0–2 are prerequisites for everything else — do not parallelize these.
- Phases 3 and 4 can be built in parallel by two people once Phase 2 is done, since red team attacking and blue team detecting are logically separate services sharing the same event bus.
- Phase 8 (AI Copilot) deliberately comes late because it depends on having real attack/detection data in the system to be useful — building it earlier means testing it against dummy data only.
- Phase 9 (CI/CD gate) is largely a wiring exercise once Phases 2–7 exist — it mainly proves the "automated, no human in the loop" story from `goal.md`.
