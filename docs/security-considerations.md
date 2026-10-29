# Security Considerations and Verification Status

## Scope

This document is a threat-model and verification checklist, not a certification or penetration-test report. The supplied local evaluation reports selected authentication, authorization, tenant-boundary, simulation-label, and lab-policy checks passing. It does not establish production security or Kubernetes isolation.

## Threats, controls, and status

| Threat | Required control | Current evidence/status | Remaining work |
|---|---|---|---|
| Unauthenticated API access | Fail-closed authentication on protected routes | Selected local paths tested | Exhaustive route inventory and live IdP tests. |
| Forged/expired JWT | Verify signature, issuer, audience, expiry, subject, tenant, and role | Selected signed-token checks reported passed | Test real Keycloak issuer, rotation, malformed and expired tokens. |
| Cross-tenant access | Tenant scope enforced server-side on every data access | Selected session/rule/Copilot paths tested | Automated exhaustive route/resource matrix. |
| User-supplied Dockerfile abuse | Isolated builder; never execute untrusted build instructions in API process | Upload policy check only; no trusted image build | Implement hardened builder, provenance, resource/time/network restrictions. |
| Sandbox escape | Cluster hardening, least privilege, default-deny network policy, pod restrictions | Live cluster unverified | Threat-model review and adversarial cluster tests. |
| False security findings | Only report scanner output from real scanner runs | Fail-closed/unavailable scanner behavior tested | Verify actual scanner version, artifacts, and reports. |
| Fake ATT&CK coverage | Require linked live attack and detection evidence | Simulated events excluded in local tests | Verify real telemetry and correlation under adversarial cases. |
| Misleading PCAP/terminal artifacts | Validate artifact provenance and content | Empty PCAP and simulated terminal labelled accurately in tests | Capture real packets and verify archive/replay. |
| Prompt injection / data leakage | Treat retrieved/user content as untrusted; scope retrieval by tenant/session; do not execute suggestions | Deterministic fallback tested; model/RAG path unverified | Test provider-backed path, retrieval scope, injection and exfiltration attempts. |
| Secret leakage | No secrets in source/archive; rotate exposed credentials | Archive-level secret hygiene needs review | Scan repository and ZIP; rotate any real credentials found. |
| Development configuration exposure | Loopback-only local mode; no demo auth on shared network | Some local boundaries tested | Deployment configuration audit and external exposure test. |
| Denial of service | Input limits, rate limits, quotas, timeouts, bounded logs/artifacts | Not fully established by supplied tests | Load/abuse testing and resource controls. |

## Mandatory safety rules

1. Use only targets for which explicit authorization exists.
2. Use disposable, isolated test environments for live scenarios.
3. Do not deploy arbitrary user-provided images into a shared cluster before the hardened build/runtime controls are verified.
4. Do not expose local development authentication or development-only OpenSearch configuration to the public internet.
5. Keep credentials out of source control, logs, screenshots, and release archives.
6. Ensure `INCONCLUSIVE` is a supported outcome when evidence or a dependency is missing.

## Security sign-off evidence

A release should include: route/role test results, tenant-isolation results, dependency and image scan reports, cluster policy evidence, secret scan results, attack-to-detection evidence, archive integrity checks, and a list of unresolved risks with owners. Absence of evidence must not be interpreted as a passing control.
