# Requirements and Dependency Status

This document distinguishes the intended architecture from what the supplied evidence currently verifies.

| Component / capability | Intended purpose | Current status in supplied evidence | Next verification |
|---|---|---|---|
| Python + FastAPI | API and workflow orchestration | Local API checks reported passed | Re-run after changes; add API contract tests. |
| React + Vite | Web dashboard | Source exists; syntax checked; production build unverified | Clean install, production build, browser tests. |
| Local authentication / signed bearer tokens | Protect API endpoints | Selected local flows tested | Exhaustive role/endpoint matrix. |
| Keycloak | External identity provider / SSO | Configuration exists; live login flow unverified | Real token issuer/audience/role/tenant tests. |
| SQLite fallback | Local development persistence | Tested in supplied local evaluation | Document as local-only fallback; test data lifecycle. |
| PostgreSQL | Persistent relational store | Connection failed in supplied run; fallback used | Actual connection, migrations, restart persistence. |
| Kafka | Event transport | Configuration/code present; live flow unverified | Produce/consume, retry, duplicate and outage tests. |
| OpenSearch | Event indexing and search | Configuration/code present; live flow unverified | Index mappings, search, isolation, retention tests. |
| MinIO | Session artifact storage | Unavailable in supplied run; local disk fallback used | Upload/download/checksum/permissions tests. |
| Kubernetes | Isolated sandbox execution | Client/cluster unavailable in supplied run | Cluster security and lifecycle tests. |
| Container image builder | Build uploaded labs safely | Not implemented/verified as a hardened pipeline | Isolated builder, image digest/provenance, policy tests. |
| Attack scenarios | Controlled test execution | Simulation locally tested | Authorized live tests in disposable targets. |
| Detection rules | Match events to detections | Local rule evaluation tested | Real telemetry, precision/recall and false-positive tests. |
| MITRE ATT&CK validation | Report evidence-backed coverage | Local reporting tested; simulated coverage excluded | Live event linkage and validation policy tests. |
| Replay | Re-emit stored events and inspect sessions | Stored event replay tested | Real capture replay and archive integrity. |
| Packet capture | Capture actual network activity | Not verified; demo reports zero packets | Validate non-empty PCAP from isolated test. |
| Scanner | Assess images/source with real tools | Fallback reports unavailable/unverified when tool missing | Real scanner run with versioned report. |
| Copilot model/RAG | Context-aware analysis assistance | Deterministic fallback tested; LLM/RAG unverified | Provider and scoped retrieval evaluation. |
| CI gate | Enforce release policy | Local simulation returns INCONCLUSIVE | Live PASS/FAIL/INCONCLUSIVE policy tests. |

## Minimum development environment

Use the versions compatible with the repository's lockfiles and dependency manifests. The supplied setup documentation calls for Python 3.11+ and Node.js/npm. Docker is optional for the local simulation profile but required for relevant container workflows. External services are needed only for the integration paths that depend on them.

## Configuration policy

- Use `.env.example` for documented variable names and placeholders.
- Keep actual `.env` files out of distributable archives and version control.
- Never reuse example passwords or signing keys in shared environments.
- Document which variables are mandatory in local simulation versus live integration profiles.
- Fail closed when security-critical configuration is missing or invalid.
