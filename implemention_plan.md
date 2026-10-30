# Cyber Range: Target-Connected Red Team / Blue Team Implementation Plan

**Audience:** Coding agent implementing the existing project  
**Priority:** Critical functionality before UI polish  
**Primary outcome:** Every lab assessment, Red Team test, and Blue Team alert must be tied to the Dockerfile/Compose project and image uploaded by the administrator. The app must never present canned output or synthetic events as real execution or real detection.

## 1. Goal and product behavior

Implement a working Cyber Range in which:

1. An **Admin** uploads a Dockerfile or Docker Compose project (including the build context/files it needs).
2. The platform validates the uploaded files, performs static configuration checks, safely builds a real container image, records its immutable digest, and scans that exact image for known vulnerabilities.
3. The platform provisions an isolated lab target from that exact image (or Compose project) and verifies the target is actually running and reachable from the dedicated testing toolbox.
4. The **Red Team** runs only approved, lab-scoped scenarios against that target. In live mode, commands must use the real target endpoint and output/exit status must come from execution. In simulation mode, the scenario must be derived from the lab's real scan/configuration evidence and explicitly labelled simulated.
5. The **Blue Team** sees vulnerability findings from actual scans and attack-detection alerts derived from collected runtime/application/network telemetry or from clearly labelled simulated events. Findings and alerts must link to supporting evidence.
6. Validation and scoring distinguish test execution, target impact, vulnerability confirmation, detection, missed detection, and inconclusive results.
7. If a builder, scanner, cluster, sensor, or dependency is unavailable, report a clear failed/unknown/inconclusive state. Never silently convert a failure into a successful build, attack, or detection.

**Important domain distinction:** The platform cannot literally attack a Dockerfile as a running system. It should assess the Dockerfile/Compose file statically, build the uploaded project into an image, scan the image, then test the running container created from that image. Simulation is allowed, but it must be target-aware and use evidence collected from that particular upload.

## 2. Existing implementation issues to fix first

Inspect the current code before editing and preserve useful working components. The following behaviors were found in the supplied project ZIP and must be addressed:

- `services/labs/service.py` runs `SafetyScanner.lint_dockerfile()` or `lint_compose()`, computes a candidate image tag, and currently sets `build_status` / lab `status` to `built` when the policy scan passes. This is not a real image build.
- `services/labs/service.py` currently accepts a single text file. A Dockerfile may need a build context (source files copied by `COPY`/`ADD`), and Compose projects may reference multiple files, local build contexts, and environment files. Do not pretend those files are present if only the YAML was uploaded.
- `services/labs/service.py` has a sample/demo lab fallback in the lab-listing path. A demo record must not be presented as an admin-uploaded or verified lab. Remove the implicit fallback or show seeded examples with an unmistakable `demo` label and never use them as a user's uploaded target.
- `services/orchestrator/service.py` explicitly returns a conflict for live Dockerfile launches because an isolated image builder is not configured. Implement a real build workflow before enabling live launch from an uploaded Dockerfile; do not bypass this guard by launching a default or unrelated image.
- `services/orchestrator/k8s_client.py` returns `execution_mode: simulated` when Kubernetes is unavailable and returns canned planned resources. Preserve the explicit distinction and ensure a simulated session never claims a real namespace or target was created.
- `services/orchestrator/k8s_client.py` currently creates the target pod from an image reference but does not establish that the image digest is the artifact built from the uploaded lab, nor does it wait for readiness and verify the target endpoint.
- `services/attack_engine/runner.py` uses scenario `expected_output` as canned output in simulation mode. Ensure canned output is never represented as real command output, a confirmed exploit, or a confirmed vulnerability. Live results must come from execution and have reliable exit/timeout status.
- `services/attack_engine/scenarios/*.yaml` contain hard-coded hostnames and examples of intrusive/destructive operations (including reverse-shell and data-dumping patterns). Scenarios must use the actual, session-specific target, be constrained to the isolated lab, be safe by default, and not execute canned or arbitrary commands outside the lab.
- `services/detection_engine/service.py` evaluates normalized events against detection rules. Keep this rules engine, but ensure each alert references a genuine triggering event and records the event's provenance (`live`, `simulated`, `replayed`, or `test-fixture`). Synthetic events may test rules, but cannot be reported as live observed activity.
- `services/orchestrator/scanner.py` already contains Dockerfile/Compose policy checks and a Trivy image-scan method. Reuse/improve these rather than inventing CVE findings. A missing/unavailable scanner must yield `unknown`/`failed`/`inconclusive`, not a clean result.
- Check actual API routes, database models, authentication/authorization, and frontend data flows before changing schemas. Keep current role boundaries: Admin manages/uploads labs; Red Team runs approved scenarios; Blue Team reviews detections; SOC investigates; users must not escape their tenant or access another tenant's lab/session/events.

## 3. Non-negotiable correctness rules

1. **No fake live results.** Do not use `expected_output`, hard-coded findings, seeded events, or demonstration data as evidence of a real attack or real detection.
2. **Truthful execution provenance.** Every scan, build, deployment, attack step, event, and detection must record whether it was `live`, `simulated`, `replayed`, `test_fixture`, or `failed` (or a clearly equivalent enum).
3. **Bind all results to the uploaded artifact.** Track `lab_id`, upload hash, build ID, immutable image digest, session ID, scenario/test ID, and timestamps. Do not launch a default image when the lab image is missing.
4. **Separate policy checks from vulnerability scans.** Static Dockerfile/Compose checks identify configuration risks. Image scanning reports CVEs/packages in the built image. Runtime testing investigates behavior of the launched target. Report these separately.
5. **A vulnerable lab can be intentional.** Do not reject a lab solely because Trivy finds vulnerabilities if the purpose is to exercise detection. Use separate safety/host-escape policy gates for dangerous build/deployment configuration and configurable vulnerability-risk policy. Unsafe host access must remain blocked.
6. **Evidence-driven detections.** An alert must contain a `triggering_event_id` and rule ID, and link to source telemetry. No telemetry means no claim of a real detection.
7. **Fail closed for live mode.** If the image wasn't actually built/scanned, target isn't ready, isolation isn't confirmed, or required telemetry is unavailable, do not mark the live lab/test as successful. Return an actionable error or `inconclusive` state.
8. **Authorization and isolation first.** Only an authorized admin may upload/build/register shared labs. Only approved scenarios may execute, and only against that lab's session target. Prevent shell injection, host filesystem mounts, Docker socket access, privileged containers, host network/namespace access, unbounded runtime, and cross-tenant references.
9. **Do not weaken security to make tests pass.** Do not disable tests, suppress errors, skip scanner gates, or relabel simulation as live.
10. **Do not rewrite unrelated subsystems.** Keep existing dashboards, auth, MITRE mappings, ingestion pipeline, rules, replay, and scoring where practical; change them only as needed for correctness and integration.

## 4. Recommended lifecycle and state model

Implement explicit states, using existing field names if possible but with unambiguous meanings:

`uploaded` → `validating` → `policy_blocked` OR `validated` → `build_queued` → `building` → `build_failed` OR `image_built` → `scanning` → `scan_failed` / `scan_inconclusive` OR `scan_complete` → `ready`.

For each session:

`creating` → `provisioning` → `provision_failed` OR `starting` → `running` → `stopping` → `stopped` / `expired` / `failed`.

- `ready` must mean a real image artifact exists, is associated with the upload, has a recorded immutable digest, and the required scans have completed. If product policy allows launching after a vulnerability scan with findings, record those findings and the policy decision explicitly.
- A successful static lint is only `validated`; it is not `built`.
- If scan tooling is unavailable, record `scan_inconclusive` or `scan_failed`, not `scan_complete` with zero findings.
- Simulation-only labs can have a separate `simulation_ready` status, but must never be mistaken for live-ready labs.
- Preserve a state transition history with timestamp, actor/system component, previous state, next state, and error/evidence reference.

## 5. Implementation phases

### Phase 0 — Map existing behavior and establish a baseline

**Files to inspect:** `app_server.py`, `shared/db.py`, `shared/schema.py`, `shared/config.py`, `services/labs/service.py`, `services/orchestrator/{service.py,k8s_client.py,scanner.py}`, `services/attack_engine/{service.py,runner.py,scenarios/*.yaml}`, `services/ingestion/*`, `services/detection_engine/*`, `services/validation_engine/*`, `services/scoring_engine/*`, `services/replay_engine/*`, `infra/k8s/*`, and `web/src/components/{LabsOverview,RedTeamConsole,BlueTeamHub,AdminOverview,SocAnalystDesk}.jsx`.

Tasks:
- Map the API endpoints, ORM models, role guards, event schemas, and frontend request/response fields.
- Run the existing unit/smoke/integration checks and record the baseline results.
- Identify all places that synthesize event records, canned attack output, demo labs, default target images, or success statuses without a real action.
- Add or update tests before changing behavior; avoid altering public API contracts unless needed, and document any unavoidable change.

**Acceptance criteria:** A short implementation note exists in `docs/` listing current flows, known gaps, baseline commands/results, and any migration required. No status is reported as implemented unless backed by code/tests.

### Phase 1 — Make lab upload and build real

**Primary files:** `services/labs/service.py`, `services/orchestrator/scanner.py`, `services/orchestrator/service.py`, `shared/db.py`, `shared/schema.py`, upload API schemas/routes, and `web/src/components/LabsOverview.jsx` / Admin views.

Tasks:
1. Support the build inputs the project intends to accept:
   - Dockerfile **plus build context** (prefer a validated archive upload with size/file-count limits and safe extraction; alternatively clearly support Dockerfile-only projects when no local files are required).
   - Compose project plus all declared build context files/configuration needed. If project upload bundles are not yet supported, return a specific, user-readable validation error for unsupported local contexts—never silently build something else.
2. Validate filenames and archive paths. Prevent path traversal, symlinks that escape the context, archive bombs, oversized files, and secrets accidentally included in logs/reports. Do not execute uploaded scripts during upload validation.
3. Run static Dockerfile/Compose safety checks. Keep policy checks distinct from vulnerability checks. Block dangerous host escape patterns (privileged mode, host PID/network, Docker socket/unsafe host mounts, etc.) from live launch.
4. Implement a real **isolated builder** (for example, a dedicated BuildKit/Buildah worker appropriate to the deployment environment). Do not run arbitrary builds inside the API process, mount the host Docker socket into an untrusted build, or give the uploaded build privileged host access.
5. Build to a unique image tag and capture the immutable image digest, builder result, logs (sanitized), and artifact metadata. The image must be provably built from the uploaded content hash/build context.
6. Change `upload_lab` so a passed lint does **not** set `status="built"`. Use explicit lifecycle states and queue/execute the real build. Handle timeout, build failure, cancellation, and cleanup.
7. Remove any implicit demo lab fallback from ordinary lab listing. If demo fixtures are retained for development, label them prominently and disable them in normal operation.
8. Remove the fallback `vulhub/struts2-core:2.3.31` from uploaded-lab launch paths. A missing built image/digest must block launch.

**Acceptance criteria:**
- Valid minimal Dockerfile/context produces a real image and records its digest.
- Dockerfile requiring a missing `COPY` file fails the build, and the lab is not marked built/ready.
- Invalid/unsafe Compose config is rejected with an actionable reason.
- Missing builder/cluster dependency is reported as unavailable; no fake image is registered as built.
- Uploaded artifact hash, build ID, image tag, and digest are linked in the database and UI.

### Phase 2 — Scan the actual built image and save findings

**Primary files:** `services/orchestrator/scanner.py`, `services/orchestrator/service.py`, database/event schemas, lab APIs, and Admin/Labs UI.

Tasks:
1. Invoke the existing Trivy image scanner against the **exact image digest** generated in Phase 1, not a guessed tag or unrelated image.
2. Capture scanner version, vulnerability DB metadata if available, image digest, timestamps, exit code, summary counts, and normalized findings.
3. Store per-finding details where possible: CVE ID, package, installed/fixed version, severity, title/description, target image digest, references, and evidence source. Keep full scanner JSON as an artifact only if appropriate, with size controls.
4. If Trivy is missing, times out, cannot pull an image, or returns malformed/failed output, record `scan_failed`/`scan_inconclusive`; never imply there are zero vulnerabilities.
5. Do not conflate a vulnerable image with unsafe-to-run configuration. Apply the configured vulnerability policy transparently while allowing intentionally vulnerable lab targets in the isolated range if permitted.
6. Add a Dockerfile/Compose configuration findings view beside—but separate from—the image CVE findings view.

**Acceptance criteria:** A known test fixture image with a known finding yields scanner-sourced evidence; the result identifies the exact digest. A scanner-unavailable test does not pass as clean. No CVE is fabricated by application code.

### Phase 3 — Provision the exact uploaded image as an isolated target

**Primary files:** `services/orchestrator/service.py`, `services/orchestrator/k8s_client.py`, `infra/k8s/{namespace-template,pod-target,pod-toolbox,network-policy-default-deny,network-policy-allow-toolbox}.yaml`, configuration, and session UI.

Tasks:
1. Provision the target from the verified digest in the session's lab record. Never use an image name supplied independently by a Red Team API request to override the admin-approved artifact.
2. Ensure Kubernetes namespace, target pod, toolbox pod, and network policies are created successfully; wait for pod readiness and report image-pull, crash-loop, and readiness failures.
3. Create an explicit service/DNS endpoint for the target and record it in session metadata. Provide the endpoint only to the authorized toolbox and approved test runner.
4. Enforce default-deny networking; allow only required toolbox-to-target traffic and narrowly scoped telemetry egress. No target access to host services, cloud metadata endpoints, production network, or other tenants.
5. Harden both build and runtime environments: no privileged target/toolbox; no host namespace access; no host Docker socket or sensitive mounts; least privilege service account; CPU/memory/PID/storage/time limits; expiration TTL and cleanup on failure.
6. Validate the actual runtime configuration. The existing target pod template currently runs target as root (`runAsNonRoot: false`)—do not blindly enforce non-root if doing so makes a deliberately vulnerable target untestable, but document and isolate such exceptions and never grant host privilege. Instrumentation sidecars must be verified as functional, not merely present in YAML.
7. Set session state to `running` only after verifying the target is ready and required isolation controls are in force. If provisioning fails, clean up partial resources and mark failure.
8. Implement deterministic teardown on expiry, manual stop, failed setup, and app restart reconciliation.

**Acceptance criteria:** A live session's recorded `lab_id`, image digest, target pod imageID, and target endpoint all match. A broken/unavailable cluster blocks live mode and never masquerades as a live session. Cross-tenant targeting is rejected. Teardown deletes the session resources.

### Phase 4 — Make Red Team scenarios target-aware and truthful

**Primary files:** `services/attack_engine/runner.py`, `services/attack_engine/service.py`, `services/attack_engine/scenarios/*.yaml`, `services/orchestrator/k8s_client.py`, and `web/src/components/RedTeamConsole.jsx`.

Tasks:
1. Change scenario parameters so all target addresses are injected from the current session's verified target endpoint. Remove hard-coded hostnames, sample IPs, fixed credentials, and assumptions that every target runs the same services.
2. Build a capability/applicability profile for each uploaded target from its scan results, service discovery, image/config metadata, and declared lab ports. Present only relevant tests or clearly mark others `not_applicable`.
3. Keep a safe approved scenario registry. The API must not let a user send arbitrary shell command strings and have them executed. Validate scenario ID, parameters, allowed argv patterns, target endpoint, rate limits, and timeouts. Do not allow shell interpolation or unrestricted `bash -c`/`python -c` escape routes. Use non-destructive, bounded checks by default; any high-impact test must be explicitly enabled for an isolated, authorized lab and be constrained to the target.
4. The live runner must execute the scenario against the actual target from the toolbox, capture stdout/stderr, exit code, timeout, execution timestamps, tool version, and target endpoint. A Kubernetes exec response that returns no reliable exit status must not be treated as successful execution.
5. Do not use YAML `expected_output` as live command output. It may be used only as clearly labelled simulated/reference output for a simulation scenario, never to claim that a command ran or an exploit succeeded.
6. Simulation must be **lab-aware**: derive its possible steps from actual findings/configuration/services of the selected lab, cite the related finding IDs or evidence, and label the output “SIMULATED — not executed against the target.” If the lab has no evidence to support a scenario, mark it `not_applicable` or `inconclusive` instead of inventing an attack success.
7. Store per-step results and outcomes using an explicit set such as `executed`, `simulated`, `blocked`, `failed`, `not_applicable`, `inconclusive`, `detected`, `missed`. Do not collapse “command ran” and “exploit succeeded” into the same status.
8. Record target artifact identity on every test step: `lab_id`, `build_id`, `image_digest`, `session_id`, scenario ID, target endpoint, execution provenance, and evidence references.

**Acceptance criteria:**
- A live scenario can show the actual target endpoint and real output/exit status.
- With Kubernetes disabled, the result is clearly simulated and no API result says the command ran live.
- A scenario using a non-existent service is `not_applicable`/failed, not a canned success.
- No scenario can target an arbitrary IP/domain, another session, or an external system.
- All target-aware simulated steps cite real evidence from that lab and are never counted as live attack execution.

### Phase 5 — Connect Blue Team to target telemetry and findings

**Primary files:** `services/ingestion/{service.py,normalizer.py,opensearch_sink.py}`, `services/detection_engine/{service.py,sigma_compiler.py,rules/*.yaml}`, `infra/k8s/pod-target.yaml`, telemetry/forwarder config, and `web/src/components/{BlueTeamHub,SocAnalystDesk}.jsx`.

Tasks:
1. Expose the image vulnerability/configuration findings from Phase 2 as a separate Blue Team vulnerability queue. Each record must link to its image digest, package/config line, scanner/rule, and evidence.
2. For attack detection, collect real telemetry from the running lab. Verify which sensors truly work in this deployment (container stdout/stderr, application/access logs, Falco/runtime events, or scoped packet capture). A sidecar placeholder is not evidence that telemetry is collected. Fix the capture/forwarding pipeline or clearly state which signals are unavailable.
3. Preserve event provenance, source type, timestamp, tenant/session/lab/image identity, original/raw evidence reference, and normalization metadata. Do not accept client-provided `tenant_id`, `session_id`, `lab_id`, or image digest as trusted without server-side authorization and reference validation.
4. Ensure a detection is created only when a configured rule matches an ingested event. Record `rule_id`, `triggering_event_id`, matched fields, rule version, and observed-vs-simulated provenance.
5. Add correlation from attack step → event(s) observed → alert(s) → validation result. Deduplicate correctly without suppressing unrelated events.
6. If a live test runs but no telemetry is available, report detection as `inconclusive` (or `unobservable`), not “detected” and not a definite miss. Mark a test `missed` only when required telemetry was functioning and the evaluation window expired without the expected alert.
7. Keep simulated alert tests available for rule validation, but label them `test_fixture`/`simulated` and exclude them from live detection metrics.
8. Add sensor health status and alert on ingestion failures, lag, or unavailable sources.

**Acceptance criteria:** A real approved test produces genuine telemetry from the target/lab, the event is ingested, and a matching Blue Team alert links back to the original event. If sensor/ingestion is disabled, a live test cannot earn a Blue Team detection score. Test-fixture events never appear as real observed telemetry.

### Phase 6 — Correct validation, scoring, persistence, replay, and reporting

**Primary files:** `services/validation_engine/*`, `services/scoring_engine/*`, `services/replay_engine/*`, `shared/schema.py`, database models/migrations, and the Red/Blue/SOC views.

Tasks:
1. Define an auditable result model joining a test step, artifact/image, session, execution evidence, observed telemetry, detections, and final assessment.
2. Score Red Team on relevant approved test execution and verified outcomes—not number of generated events, canned output, or claimed success. Distinguish discovery, attempt, verified impact, and unverified attempt.
3. Score Blue Team on correct alerts from required genuine telemetry, timeliness, precision, and coverage. Exclude simulated/replayed/test-fixture results from production/live scores unless a dedicated simulation scorecard is selected.
4. Use explicit ground truth per scenario: expected observable signals, required sensor sources, detection window, and conditions under which a test is not applicable. Do not score telemetry-unobservable tests as misses.
5. Preserve event replay and evidence manifests, including original provenance. Replayed logs must remain replayed, not become live events on re-ingestion.
6. Provide a per-lab assessment report with separate sections for static policy findings, image vulnerabilities, live Red Team steps, simulated steps, observed events, Blue Team detections, misses, inconclusive results, recommendations, and evidence links.

**Acceptance criteria:** Reports can trace a result back to the uploaded artifact and evidence. Simulated/test fixtures do not inflate live scores. Missing evidence produces `inconclusive`, not a positive or negative claim.

### Phase 7 — Frontend, roles, and operator experience

**Primary files:** `web/src/components/LabsOverview.jsx`, `AdminOverview.jsx`, `RedTeamConsole.jsx`, `BlueTeamHub.jsx`, `SocAnalystDesk.jsx`, and shared API/client code.

Tasks:
- Admin upload page: upload status, validation findings, build progress/failure, image digest, image scan summary, policy decisions, and supported project/context formats.
- Lab details: clearly show the uploaded artifact, build ID/digest, scanner status, findings, and whether live launch is currently possible.
- Red Team: choose a lab/session first; show target identity and scope; display live/simulated mode persistently; show each step's real execution status, output, exit status, and evidence.
- Blue Team: provide vulnerability queue separately from observed attack alerts; show original event, rule match, provenance, target/session, and evidence.
- SOC: investigation timeline linking scan findings, attack steps, observed telemetry, alerts, and response/validation.
- Make status labels explicit and consistent: `Live`, `Simulated`, `Replayed`, `Test fixture`, `Failed`, `Inconclusive`, `Not applicable`.
- Enforce role-based UI visibility, but never rely on hidden UI buttons as security; validate permissions on the server for every API request.
- Show clear errors and remediation steps rather than successful-looking empty dashboards.

**Acceptance criteria:** A user can follow one lab from admin upload to image scan to session to Red Team test to Blue Team alert, and every screen displays the same lab/session/image identity and provenance.

### Phase 8 — Hardening, regression tests, documentation, and release gate

Tasks:
1. Add unit, integration, and end-to-end tests covering successful and failing workflows, with fixtures labelled as test fixtures.
2. Test tenant/role authorization, archive path traversal, oversized uploads, invalid YAML, missing build context, unsafe Compose settings, image-build timeout, scanner missing/timeout, image-pull failure, target not ready, toolbox failure, command allowlist bypass, telemetry absence, detection deduplication, and session cleanup.
3. Test both modes deliberately:
   - **Simulation mode:** target-aware results are derived from the selected lab's actual evidence, explicitly simulated, and do not claim live execution.
   - **Live mode:** no tests pass unless the image is built, scan state is explicit, the exact image is deployed, the target is reachable, execution is observed, and telemetry/detection evidence is collected as required.
4. Add a deterministic end-to-end fixture lab that is harmless and specifically built to exercise a known configuration flaw or harmless test condition. The test should verify artifact linkage, scanning, target startup, test execution or simulation, telemetry, alert correlation, and scoring. Do not depend on a real exploit against an external system.
5. Update `README.md`, `docs/architecture.md`, `docs/requirements.md`, `docs/plan.md`, `docs/security-considerations.md`, `docs/setup.md`, and relevant evaluation docs to match implemented behavior. Document prerequisites for the actual builder, Trivy, Kubernetes cluster, telemetry sources, and local simulation mode.
6. Add a release checklist that blocks release claims such as “live attack testing”, “vulnerability scan complete”, or “Blue Team detected the attack” unless corresponding evidence exists.
7. Review repository hygiene: do not package local `.env` secrets, SQLite databases containing user data, runtime logs, Python bytecode, frontend `node_modules`, or generated session artifacts in release ZIPs. Keep `.env.example` with placeholders.

**Acceptance criteria:** All tests pass in CI/local test mode. Live integration tests are marked unavailable—not passed—when their external prerequisites are missing. Documentation tells the truth about which live workflows were verified. The package contains no secrets or unintended runtime artifacts.
