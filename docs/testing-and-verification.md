# Testing and Verification Plan

## Evidence levels

1. **Static/source checks:** syntax and format checks only.
2. **Unit/local tests:** one component or route in the local simulation profile.
3. **Integration tests:** application communicates with a real configured dependency.
4. **End-to-end tests:** a complete user workflow crosses the real components intended for deployment.
5. **Operational/security tests:** resilience, isolation, recovery, and abuse cases are tested in a controlled environment.

Do not use evidence from a lower level to claim a higher level.

## Supplied historical evidence

The archive includes a report of 36/36 local API/security-behaviour checks passing, syntax checks, and an HTTP-driven local demo. The recorded run explicitly had zero live attack steps, zero verified coverage, and zero captured packets. The frontend production build was not verified.

## Required verification matrix

| Test group | Minimum evidence | Status from supplied archive |
|---|---|---|
| Backend startup/health | Clean startup log and health response | Locally reported passed |
| Auth/JWT | Valid, invalid, expired, wrong issuer/audience, missing claims | Selected local cases reported passed; live IdP unverified |
| RBAC | Role × endpoint access matrix | Selected paths reported passed; exhaustive matrix pending |
| Tenant isolation | Cross-tenant reads/writes for every resource family | Selected paths reported passed; exhaustive matrix pending |
| Lab upload/build | Unsafe input rejected; safe input built in isolated service | Policy screening tested; builder not implemented/verified |
| Attack execution | Real approved target, actual execution evidence | Simulation only in supplied run |
| Telemetry | Actual sensor events with provenance | Not verified |
| Detection | Real event produces linked detection; false-positive tests | Local event evaluation tested; live source unverified |
| ATT&CK coverage | Live attack + linked detection + auditable policy | No verified live coverage in supplied run |
| Database | Persistence after restart against PostgreSQL | SQLite fallback used; PostgreSQL unverified |
| Kafka | Producer/consumer, retry, duplicate, outage | Unverified |
| OpenSearch | Indexing, query filters, tenant scope | Unverified |
| MinIO | Upload/download/checksum/permission | Local disk fallback used; MinIO unverified |
| Replay/PCAP | Valid archive and PCAP with packets | Event replay tested; real PCAP not verified |
| Scanner | Actual scanner execution and report | Unavailable/unverified fallback tested |
| Copilot | Provider response, scoped retrieval, prompt-injection tests | Deterministic fallback only |
| CI gate | Live PASS/FAIL and missing-evidence INCONCLUSIVE | Simulation behavior tested; live enforcement unverified |
| Frontend | `npm ci`, `npm run build`, browser acceptance | Production build unverified |
| Operations | Backup/restore, load, logging, recovery | Not established by supplied evidence |

## Repeatable test procedure

1. Record Git commit or source archive hash.
2. Record OS, Python, Node/npm, and dependency versions.
3. Start with a clean environment and documented configuration.
4. Run static checks and local evaluation.
5. Run integration tests against each actual dependency.
6. Run an end-to-end workflow against an isolated authorized target.
7. Preserve logs, redacting secrets and personal data.
8. Report passed, failed, skipped, blocked, and inconclusive counts separately.
9. Never turn a skipped or unavailable integration into a pass.

## CI gate semantics

- `PASS`: required live evidence exists and all configured policy conditions pass.
- `FAIL`: verified evidence violates at least one release-blocking condition.
- `INCONCLUSIVE`: required evidence/dependency is missing, simulated, stale, or unverifiable.

The precise conditions must be versioned and documented. A score alone should not silently determine a pass.
