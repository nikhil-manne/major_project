# Implementation Status and Current Project Boundary

**Snapshot basis:** supplied project archive and its evaluation artefacts. The included evaluation report is dated 24 October 2026.

## 1. Executive summary

The current deliverable is best described as a **working local simulation prototype with several backend security behaviours tested**, plus frontend source and infrastructure integration code. It is **not yet a fully verified, live cyber-range platform**.

The supplied evaluation artefacts report 36/36 local API/security-behaviour checks passing and a scripted HTTP demonstration completing against a local Uvicorn server. The same evidence explicitly reports zero live attack steps, zero verified ATT&CK coverage, no captured packets, no verified live sensor pipeline, and no successful frontend production build in that review environment.

This is the boundary that all project documents, presentations, and demonstrations should preserve.

## 2. What is implemented or locally demonstrated

| Area | Current status | Evidence / boundary |
|---|---|---|
| FastAPI backend | Locally verified | Supplied evaluation reports API health and tested endpoint responses in simulation mode. |
| Local login and role checks | Locally verified for tested paths | Local signed bearer-token and authorization paths were tested. This does not verify the full Keycloak SSO experience. |
| Tenant/session boundary checks | Locally verified for selected paths | Tests report rejection of selected cross-tenant requests and trusted-ID spoofing. This is not exhaustive endpoint security proof. |
| Lab upload policy screening | Implemented and locally tested | Upload is a policy-check step. It does not build a container image. |
| Attack scenario runner | Simulation workflow locally verified | Demo reports five simulated steps, one blocked step, and zero live steps in the recorded run. |
| Detection rules | Local evaluation tested | Rules can be evaluated against local/simulated events. Live Falco/Suricata or production log ingestion is not verified. |
| Local event persistence | SQLite fallback tested | Persistence outside the in-memory cache was tested. PostgreSQL operation is not verified by the supplied run. |
| Replay of stored events | Local event replay tested | The supplied demo reports six attack events re-emitted and six replay detections. Real packet replay is not verified. |
| Coverage/scoring/CI gate | Local behavior tested | Simulation is explicitly excluded from verified ATT&CK coverage; the CI result is INCONCLUSIVE in simulation; the score is heuristic. |
| Copilot | Deterministic fallback tested | The fallback discloses that it is not an LLM or RAG pipeline. Actual provider/model retrieval is not verified. |
| React frontend | Source present; build unverified | JS/JSX syntax was checked, but a production Vite build did not complete in the supplied review environment. |
| Infrastructure configuration | Files present | Compose/Kubernetes/Keycloak/OpenSearch/PostgreSQL/MinIO-related files exist; presence is not live integration proof. |

## 3. What is not currently established as complete

The supplied evidence does not establish that the following are fully operational end to end:

- A clean, successful frontend production build and browser-level acceptance test.
- Keycloak-issued tokens and the complete real identity-provider login flow.
- PostgreSQL persistence and restart/migration behaviour.
- Kafka event delivery, consumer processing, and failure recovery.
- OpenSearch indexing, mappings, and tenant-scoped query behaviour.
- MinIO archive upload/download and integrity checks.
- A real Kubernetes cluster creating and destroying isolated labs safely.
- A hardened container image-building pipeline for uploaded Dockerfiles.
- Real attack execution against an authorized isolated target.
- Real Falco/Suricata or equivalent sensor ingestion and verified attack-to-detection linkage.
- Valid packet capture containing actual packets and real PCAP replay.
- Live scanner findings from Trivy/Hadolint or another configured scanner.
- Production model/RAG-backed Copilot behavior.
- A CI gate that returns PASS/FAIL based on a fully verified live run and enforced release policy.

## 4. Correct wording for reports and viva

**Recommended:** “The project currently implements a local simulation workflow and has reported passing 36/36 local API/security-behaviour checks. Live infrastructure, real attack/sensor integration, and frontend production build verification remain future work.”

**Avoid:** “The complete cyber range is production-ready,” “all attacks are detected,” “100% ATT&CK coverage,” or “the CI gate guarantees a secure release.” The supplied evidence does not support those statements.

## 5. Completion rule

A component is not considered fully verified merely because its source file, UI page, route, configuration, or test stub exists. Mark a capability **Verified** only after a repeatable test exercises the real intended dependency and records an observable result.
