# Implementation Plan

This plan separates work already evidenced in the supplied local evaluation from work still required. The phases are ordered by dependency; they are not claims that each phase has been completed.

## Phase 0 — Local prototype and security-behaviour baseline
**Status: Local checks reported as passed.**

- FastAPI routes and local simulation profile.
- Local auth and selected role/tenant boundary checks.
- Lab policy screening without falsely claiming image builds.
- Simulated attack and local detection evaluation.
- SQLite fallback persistence and stored-event replay.
- Coverage, scoring, and CI responses that disclose simulation limitations.

**Evidence:** supplied evaluation artefacts report 36/36 local checks passed. This is a historical report and should be rerun after changes.

## Phase 1 — Frontend build and local acceptance
**Status: Pending verification.**

- Perform clean `npm ci` using the committed lockfile.
- Run `npm run build`.
- Start backend and frontend together.
- Test login, role-based page access, API error states, empty states, and session workflows in a browser.
- Record browser screenshots and build/test logs.

**Exit criteria:** production build succeeds; critical UI flows pass; failures are documented rather than hidden.

## Phase 2 — External data services
**Status: Configuration/code present; live integration unverified.**

- Validate PostgreSQL schema and persistence across restarts.
- Validate Kafka topics, producer/consumer delivery, retry behaviour, and duplicate handling.
- Validate OpenSearch mappings, indexing, search filters, and tenant boundaries.
- Validate MinIO archive upload/download and checksum verification.

**Exit criteria:** integration tests use actual services, persist across restart, and capture evidence for success and failure cases.

## Phase 3 — Identity and authorization integration
**Status: Local JWT behaviour tested; real IdP flow unverified.**

- Configure Keycloak realm, client, issuer, audience, roles, and tenant claims.
- Verify real signed tokens and key rotation behaviour.
- Test all roles against all sensitive endpoints, not only the dashboard.
- Test expired, malformed, wrong-issuer, wrong-audience, and wrong-tenant tokens.

**Exit criteria:** automated integration suite proves authentication and authorization at API boundaries.

## Phase 4 — Secure lab build and Kubernetes execution
**Status: Not verified live; hardened image builder is outstanding.**

- Implement an isolated build service for user-supplied source/Dockerfiles.
- Produce immutable image references, scan results, provenance, and build logs.
- Configure a real Kubernetes cluster with default-deny network policies, least-privilege service accounts, pod security controls, resource quotas, secrets controls, and cleanup TTLs.
- Test successful launch, rejected launch, timeout, cancellation, and cleanup after failure.

**Exit criteria:** a lab can be built and launched safely in a test cluster with auditable provenance and demonstrated isolation.

## Phase 5 — Real attack and sensor-to-detection validation
**Status: Simulation tested; live workflow unverified.**

- Select a small set of safe, authorized test scenarios.
- Execute only against isolated disposable targets.
- Collect actual host/network telemetry.
- Normalize events and preserve trustworthy session/tenant linkage.
- Validate detection matches and false-positive/false-negative cases.
- Count ATT&CK coverage only when live attack evidence is linked to a detection according to the documented policy.

**Exit criteria:** each supported scenario has repeatable execution, telemetry, detection, and evidence traceability.

## Phase 6 — Archive, replay, scoring, and CI policy
**Status: Local behavior tested; production path unverified.**

- Verify real terminal/session artifacts and PCAP files with actual packet records.
- Verify archive round-trip and replay against captured events.
- Document score inputs, weights, limitations, and reproducibility.
- Enforce CI outcomes: `PASS`, `FAIL`, or `INCONCLUSIVE`; unknown/unverified evidence must not silently pass.
- Test policy thresholds and release-blocking behavior.

**Exit criteria:** gate outcomes are explainable, reproducible, and enforce the configured policy.

## Phase 7 — Copilot, observability, and release hardening
**Status: Deterministic fallback tested; model/RAG path unverified.**

- Integrate a configured model provider and scoped retrieval only if required.
- Test prompt-injection resistance and tenant/session retrieval boundaries.
- Add structured logs, metrics, alerting, backup/restore, dependency pinning, and operational runbooks.
- Conduct a security review and deployment rehearsal.

**Exit criteria:** production claims are supported by an evidence pack, threat-model review, operational runbooks, and release checklist.
