# Future Roadmap and Priorities

## Priority summary

| Priority | Workstream | Why it comes next | Completion evidence |
|---|---|---|---|
| P0 | Frontend clean build | The UI cannot be considered build-verified until bundling succeeds. | `npm ci`, `npm run build`, browser acceptance results. |
| P0 | Secret and release hygiene | Prevent accidental exposure of credentials or development-only settings. | Clean distributable, secret scan, reviewed `.env.example`, documented rotation if needed. |
| P1 | PostgreSQL/Kafka/OpenSearch/MinIO integration | Required for the target event and archive architecture. | Repeatable integration tests against real services. |
| P1 | Keycloak SSO and exhaustive RBAC | Local token tests do not prove the full IdP workflow. | Token-validation and role/tenant test matrix. |
| P1 | Hardened image build service | Current upload path policy-checks files but does not build images. | Isolated build, scan, immutable tag/digest, provenance, rejection tests. |
| P1 | Kubernetes isolation | Needed for safe live lab execution. | Cluster test evidence for network isolation, quotas, pod restrictions, TTL, cleanup. |
| P2 | Real telemetry and attack-to-detection linkage | Required for meaningful live ATT&CK coverage. | Scenario-by-scenario attack, sensor, detection, and correlation evidence. |
| P2 | Real packet capture and archive integrity | The current recorded demo reports no packets. | Valid PCAP with packets, archive checksum, successful retrieval/replay. |
| P2 | Production scanner integration | Local fallback must not fabricate findings. | Scanner version, command, exit code, and reproducible report for test images. |
| P2 | Model/RAG Copilot | Current verified mode is deterministic fallback. | Provider health, tenant-scoped retrieval tests, injection tests, output evaluation. |
| P3 | Production operations | Required before shared or internet-facing use. | Monitoring, backup/restore, incident runbook, load test, security review. |

## Suggested milestones

### Milestone A — Reproducible local demo
Build passes, startup steps work from a clean checkout, and the documented local simulation can be reproduced by another developer.

### Milestone B — Integrated service backbone
PostgreSQL, Kafka, OpenSearch, and MinIO integrations pass independent tests, including restart and failure scenarios.

### Milestone C — Secure isolated execution
A hardened build pipeline and Kubernetes sandbox can safely launch and clean up approved test labs.

### Milestone D — Evidence-backed validation
At least one approved live scenario produces real telemetry, a verified detection, an evidence-linked ATT&CK result, and a replayable archive.

### Milestone E — Release-gate proof
The CI gate blocks a deliberately failing test, allows a passing test under explicit policy, and returns `INCONCLUSIVE` when evidence is missing.

## Dependencies and sequencing

Do not begin broad live-attack coverage before identity, image building, sandbox isolation, and event provenance are verified. Do not describe coverage or CI results as production-grade until the real telemetry and evidence linkage work end to end.
