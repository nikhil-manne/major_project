# V3 Sandbox Fixes and Evaluation Report

**Review date:** 24 October 2026  
**Reviewed source:** the uploaded V3 project, with fixes applied to this copy  
**Evaluation profile:** local SQLite fallback + simulated attack mode  
**Important:** this report is not a production-security audit and does not claim that external infrastructure or live attacks were verified.

## Executive verdict

The source changes passed **36/36 local API/security-behavior checks** and the scripted demo completed against a real local Uvicorn HTTP server. Python compilation and source-format parsing also passed. This establishes that the tested backend paths work in the local simulation profile; it does **not** establish that the entire cyber range is fully working.

The most important remaining gap is the difference between the current simulation workflow and a fully integrated live platform. The demo correctly produced zero live attack steps, zero verified ATT&CK coverage, and no network packets captured. The frontend production build could not be completed in this review environment because dependency installation was unavailable/broken, so the frontend is syntax-checked but not build-verified.

## Fixes applied

1. **Authentication fails closed.** Removed the unverified-token/admin fallback. JWT verification validates signature, issuer, audience, expiry, and required subject/tenant/role claims against configured JWKS. Development identity headers require an explicit setting and a loopback caller. `.env.example` now disables development auth by default.
2. **Tenant and session boundaries tightened.** Raw event payloads cannot assign their own trusted tenant, session, or build IDs. Session, replay, Copilot, and detection-rule paths use tenant-scoped access checks. Session-filtered event queries exclude sessionless events.
3. **Uploaded Dockerfiles are not falsely marked as built.** Upload currently performs a policy check, sets `policy_checked`, and does not invent an image tag. Launching an unbuilt upload is rejected. Building arbitrary uploaded Dockerfiles remains to be implemented as a separate hardened build pipeline.
4. **No synthetic vulnerability findings.** Scanner results are only treated as verified when a real scanner run supplies them. Missing Trivy or scanner errors yield an unavailable/unverified result, not fabricated CVEs.
5. **Simulation and live execution are distinguished.** Attack results state live, simulated, blocked, or inconclusive outcomes. Simulation output is not treated as proof of an exploit. Simulated events cannot produce verified ATT&CK coverage.
6. **Terminal and network artifacts are labelled accurately.** A simulated terminal transcript is marked `simulated`, not a verified live terminal recording. A header-only or invalid PCAP is marked unavailable, with zero packet records, rather than reported as captured traffic.
7. **Event persistence and custom rules.** Added/tested relational event persistence in the local database fallback. Custom detection rules are tenant-scoped, committed before activation, and their compiled query is serialized as JSON for the text database column and decoded when listed.
8. **Coverage, score, and CI claims are constrained.** Coverage requires a linked live attack-to-detection event. Readiness is explicitly a heuristic, not a production certification. A CI gate running in simulation returns `INCONCLUSIVE`, not `PASS`.
9. **Copilot fallback is honest.** The local deterministic fallback discloses that it is neither a language model nor retrieval-augmented analysis, and does not claim sensors or live scanning are working without evidence.
10. **Frontend and repository hygiene.** Fixed the MITRE view so an empty active-session selection does not accidentally query aggregate coverage. Removed stale build/dependency output and the local `.env` from the deliverable; added standard ignore rules and kept `.env.example` with placeholders.

## Test results

### Automated local suite

| Check group | Result |
|---|---:|
| Fail-closed auth, signed JWT validation, development-auth boundary | Passed |
| Tenant claim spoofing and cross-tenant access checks | Passed |
| Lab policy check and rejection of unbuilt lab launch | Passed |
| Simulated attack execution labels and role restrictions | Passed |
| Detection evaluation, custom-rule persistence, cross-tenant rule rejection | Passed |
| Event filtering and persistence beyond in-memory cache | Passed |
| Simulated ATT&CK coverage excluded from verified coverage | Passed |
| PCAP and terminal recording provenance | Passed |
| Scoring and CI-gate inconclusive behavior in simulation | Passed |
| Copilot fallback honesty and tenant scoping | Passed |
| Demo counts and absence of fabricated scanner findings | Passed |
| **Total** | **36/36 passed** |

Commands run:

```bash
python -m compileall -q .
python scripts/evaluate_local.py
python scripts/test_integration.py
```

`test_integration.py` delegates to the same explicit local evaluation suite; it is not an independent 36-test suite.

### Source-format checks

- Python AST parsed: **41 files**
- JSON parsed: **4 source/config files**
- YAML documents parsed: **17 files**
- JavaScript/JSX syntax transpile: **12 files**, zero syntax errors

These checks verify source syntax/format only; they do not replace a frontend bundler build or type-check.

### HTTP-driven demonstration

The updated `scripts/run-demo-scenario.py` completed against a separately started local Uvicorn server using HTTP requests:

| Demo step | Observed result |
|---|---|
| API health | `ok`, configured mode `simulation` |
| Quick demo | 0 live steps, 5 simulated steps, 1 blocked step; 7 detections fired |
| Coverage | 0 tested live techniques, 0 covered, 0 gaps, 3 simulated techniques |
| Archive | Created; packet capture `unavailable`; 0 packets |
| Replay | 6 attack events re-emitted; 6 replay detections triggered |
| Copilot | `local_deterministic_demo_fallback` |
| Heuristic score | 38.8 in this run; not a production certification |

The values above are observed from this run and are not benchmarks or claims of real live attacks/sensors.

## Feature status after these fixes

| Feature | Status | What this evaluation proves / does not prove |
|---|---|---|
| FastAPI backend | **Verified locally** | Server starts and tested API endpoints respond in the local profile. |
| JWT authentication logic | **Locally tested; IdP not verified** | Signed JWT validation was tested with a temporary test key/JWKS. Real Keycloak token issuance, mapper behavior, signing-key rotation and UI login remain unverified. |
| React dashboard | **Source syntax checked; build unverified** | 12 JS/JSX files transpile syntactically. No successful Vite production build was obtained in this sandbox. |
| Lab upload/policy screening | **Verified in local test** | Upload is a policy-check stage only; no image is built. |
| Container image builder | **Not implemented/verified** | A hardened builder (e.g. isolated Kaniko/build service), image provenance and artifact handoff are still required. |
| Kubernetes sandbox | **Integration code present; unverified live** | Kubernetes Python SDK/cluster was unavailable in this environment. NetworkPolicy and pod security must be tested in a real cluster. |
| Attack scenarios | **Simulation verified; live execution unverified** | The demo ran with zero live steps. Tool output is not treated as proof that an exploit succeeded. |
| Detection rules | **Local rules and custom-rule persistence verified** | Actual Falco/Suricata or production log ingestion is not verified. Rule precision and false-positive rates need more test cases. |
| Event store | **SQLite fallback tested** | PostgreSQL persistence/restarts, Kafka delivery, and OpenSearch indexing/search were not available for this run. |
| MITRE ATT&CK coverage | **Local reporting tested** | The test intentionally produced 0 verified covered techniques because only simulated data was present. Full ATT&CK coverage is not claimed. |
| Replay | **Stored event replay tested** | Six stored events replayed and six detections matched in the demo. Real packet replay is not verified. |
| Network capture | **Not verified** | No PCAP packet records were captured. The archive accurately labels capture unavailable. |
| Scanner | **Fail-closed fallback tested** | Trivy/Hadolint was not available; real image scanning and verified CVE results remain untested. |
| Readiness score | **Heuristic calculation tested** | It is not a security certification or proven release-readiness rating. |
| AI Copilot | **Deterministic fallback tested** | No real model or retrieval-augmented pipeline was verified; provider configuration/output quality need a separate test. |
| CI security gate | **Local simulation behavior tested** | Gate was inconclusive in simulation and its report persisted. A live policy-enforced release gate remains unverified. |
| MinIO archives | **Local archive path tested** | MinIO was unavailable; object-storage upload/download was not verified. |

## Environment blockers

The review environment did not provide a working Kubernetes cluster, Kubernetes Python client, PostgreSQL driver/service, Kafka, OpenSearch, MinIO, or Trivy. The backend therefore used its local SQLite/fallback paths. These are external test blockers, not evidence those services are broken when properly installed and configured.

The frontend production build could not be completed: the prebundled dependencies were from an incompatible environment, the Linux-specific Rollup package was missing, and dependency installation did not complete successfully in this sandbox. For that reason the frontend is **not build-verified**. Use a clean local install (`npm ci`) with the repository's lockfile, then run `npm run build` and test the UI against the backend.

## Live verification still required

Before describing the *total platform* as fully working, verify these on a properly provisioned machine:

1. Clean frontend install, production build, and manual smoke test of each dashboard page.
2. Keycloak-issued tokens with role/tenant claims, UI login/refresh, and denied cross-tenant requests.
3. PostgreSQL persistence across restarts and Kafka producer/consumer event flow.
4. OpenSearch index templates, event indexing, and scoped queries.
5. MinIO archive upload/download and integrity checks.
6. Isolated, hardened Kubernetes namespace lifecycle, target/toolbox pods, network policies, quotas, and teardown.
7. A real image build and Trivy scan of the resulting immutable image digest.
8. A controlled live test that produces real telemetry, a linked detection, and a repeatable measured result.
9. A PCAP containing actual packet records, retrieval from the sandbox, and replay validation.
10. CI policy tests demonstrating both a legitimate `PASS` and a known-failing `FAIL`, with correct audit evidence.
11. More cases for rule precision, false positives, missed detections, and repeated-run consistency.

## Final verdict

**The modified V3 backend's local simulation workflow is working for the 36 checks covered here. The entire product is not yet fully working or verified.** In particular, live Kubernetes attacks, real sensors, real packet capture, external infrastructure, real Copilot/RAG, and the frontend production build remain unverified. The project is now more honest about these limits and fails closed in several places where earlier code could imply successful behavior without evidence.
