# Release and Submission Checklist

## Documentation
- [ ] README, setup, architecture, schema, plan, roadmap, and demo use consistent status labels.
- [ ] Every feature claim has a source/test/evidence reference.
- [ ] Simulated workflows are explicitly identified as simulated.
- [ ] External product comparisons cite current official sources in the final report.
- [ ] Old evaluation logs are labelled with their run date and source revision.

## Repository and secrets
- [ ] No real `.env`, credentials, signing keys, tokens, or private data are included in the release archive.
- [ ] `.env.example` contains placeholders only.
- [ ] Any previously exposed secrets have been rotated.
- [x] `.gitignore` excludes local environments, caches, databases, logs, and generated artifacts where appropriate. *(test DBs + build_contexts added 2026-10-30)*
- [ ] Dependency manifests and lockfiles are included and consistent.

## Build and test
- [ ] Clean Python dependency installation succeeds.
- [x] Local evaluation suite passes on a clean checkout. *(36/36 passed — 2026-10-30)*
- [ ] `npm ci` succeeds.
- [x] `npm run build` succeeds. *(0 errors, 43 modules — 2026-10-30)*
- [ ] Browser acceptance tests pass for login, roles, main pages, and API error states.
- [ ] Test results identify skipped/unavailable external services explicitly.
- [x] Target-connected range test suite passes. *(14/14 passed — 2026-10-30)*

## Security and live integration
- [ ] Keycloak token and role mapping are tested if Keycloak is claimed as integrated.
- [ ] PostgreSQL persistence and migrations are tested across restart.
- [ ] Kafka producer/consumer behaviour is tested.
- [ ] OpenSearch mappings and tenant-scoped searches are tested.
- [ ] MinIO archive round-trip and integrity are tested.
- [x] Hardened image build pipeline implemented: upload → static policy check → isolated build → Trivy scan → digest-gated launch. *(2026-10-30)*
- [ ] Kubernetes isolation and cleanup are tested in a real cluster.
- [ ] Live attacks run only against authorized disposable targets.
- [ ] Real sensor events and detection linkage are demonstrated.
- [x] ATT&CK coverage counts only evidence meeting the documented live verification policy. *(provenance field + navigator.py 2026-10-30)*
- [ ] Real PCAPs are validated for actual packet records.
- [ ] CI gate handles PASS, FAIL, and INCONCLUSIVE correctly.

## Submission language
- [ ] Do not call the platform production-ready without production-like evidence.
- [ ] State the current implementation boundary and future work clearly.
- [ ] Include known limitations and a prioritized roadmap.
