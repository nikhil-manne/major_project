# Evaluation Summary — Local Simulation Profile

**Evidence date in supplied report:** 24 October 2026  
**Profile:** local SQLite fallback and simulated attack mode  
**Interpretation:** historical evaluation evidence from the supplied archive; not a new test run or production-security audit.

## Summary

The supplied evaluation report states that **36/36 local API/security-behaviour checks passed** and the scripted demonstration completed against a local Uvicorn HTTP server. Source-format checks also reportedly passed: Python AST parsing for 41 files, JSON parsing for 4 files, YAML parsing for 17 documents, and JavaScript/JSX syntax transpilation for 12 files.

These results support the tested local simulation workflow. They do not prove the complete live platform works.

## Key local checks reported

- Protected endpoints reject unauthenticated requests in tested paths.
- Signed-token validation rejects selected invalid tokens.
- Selected cross-tenant access and trusted-ID spoofing attempts are rejected.
- Uploaded Dockerfiles are policy-checked but are not falsely treated as built images.
- Simulated attack outcomes are labelled as simulated.
- Simulated events do not count as verified ATT&CK coverage.
- Empty/header-only PCAPs are not presented as captured traffic.
- The deterministic Copilot fallback discloses its limitations.
- A simulation-only CI gate returns `INCONCLUSIVE`.
- Local event persistence and stored-event replay paths are tested.

## Recorded demonstration

The supplied HTTP demo reported: zero live steps; five simulated steps; one blocked step; seven detections; zero covered live ATT&CK techniques; unavailable packet capture with zero packets; six replayed attack events; six replay detections; and deterministic Copilot fallback mode. The reported readiness score of 38.8 is a heuristic for that run only.

## Explicitly unverified in the supplied run

- Successful frontend production build.
- Live Keycloak login and token issuance.
- PostgreSQL persistence.
- Kafka event transport.
- OpenSearch indexing and searching.
- MinIO object storage.
- Live Kubernetes sandbox operations and isolation.
- Hardened image building.
- Live attack execution and real sensor ingestion.
- Real packet capture/replay.
- Real scanner findings.
- Provider-backed LLM/RAG Copilot.
- Production CI release enforcement.

## Reproduction commands reported

```bash
python -m compileall -q .
python scripts/evaluate_local.py
python scripts/test_integration.py
```

The supplied report says `test_integration.py` delegates to the same evaluation suite; do not count it as an independent second 36-test suite.

## Conclusion

The appropriate conclusion is **“local simulation and selected security behaviours tested”**, not “full cyber range production-ready.” Repeat the checks after code changes and create separate integration evidence for each external dependency before upgrading any status.
