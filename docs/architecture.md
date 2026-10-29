# Architecture: Current Profile and Target Design

## 1. Architecture status

The repository contains a FastAPI application, service modules, a React/Vite frontend, and infrastructure configuration for external services. The supplied evaluation verifies selected local simulation paths only. The diagram below therefore separates the **verified local path** from the **target integrations**; it must not be read as proof that every arrow is currently live.

## 2. Current local simulation path

```text
Browser / React source (production build not yet verified)
                |
                v
        FastAPI application
                |
       local auth + role checks
                |
   +------------+--------------------------+
   |            |             |            |
   v            v             v            v
Lab policy   Simulated     Local rule    Copilot fallback
screening    scenarios     evaluation    (deterministic)
   |            |             |            |
   +------------+-------------+------------+
                |
                v
       local relational fallback
                |
       event archive / replay
                |
                v
   coverage, heuristic score, CI result
   (simulation does not count as live coverage)
```

This describes the local workflow represented in the supplied evaluation. Exact runtime details can vary with configuration; the evaluation reports SQLite/local disk fallbacks when external dependencies were unavailable.

## 3. Target integration architecture

```text
React dashboard
      |
FastAPI API + authentication/authorization
      |                 \
      |                  Keycloak (target IdP; live flow unverified)
      |
  Lab policy -> hardened image builder -> image registry
                                      |
                                      v
                             Kubernetes isolated lab
                           /           |             \
                    attack runner   target         sensors
                                      |           /       \
                                      +------ telemetry ------+
                                                           |
                                                      Kafka topics
                                                           |
                                                     normalizer
                                                           |
                                                     OpenSearch
                                                           |
                           detection -> validation -> score/CI decision
                                                           |
                                                  archive / replay
                                                           |
                                                         MinIO
```

This is a target design. The supplied evidence does not verify the complete live chain.

## 4. Components and boundaries

- **API application:** exposes workflows and applies authentication/authorization checks. Local routes and selected checks were exercised in the supplied evaluation.
- **Lab policy screening:** checks uploaded lab definitions. It does not currently build uploaded Dockerfiles into trusted images.
- **Attack engine:** supports explicit simulated/live outcome labelling. The recorded demo had zero live steps.
- **Detection engine:** evaluates rules against available events. Live sensor feeds are not verified.
- **Ingestion and normalizer:** code exists for event normalization and external sinks. Real Kafka/OpenSearch operation remains unverified in the supplied run.
- **Validation/scoring:** reports coverage and a heuristic readiness score. Simulated events must not count as verified live coverage; score is not certification.
- **Replay/archive:** local event replay works in the reported demo. MinIO and real PCAP round-trip are unverified.
- **Copilot:** deterministic local fallback is verified; provider-backed LLM/RAG is not.
- **Frontend:** React components exist, but the supplied review did not complete a production build.

## 5. Key data flow for a future live scenario

1. A permitted user starts a lab in a hardened isolated environment.
2. An approved scenario executes against that target.
3. Sensors produce real events with traceable session metadata.
4. The ingestion layer validates and normalizes events.
5. Detection rules match the telemetry and produce linked detection evidence.
6. Validation associates the live attack step with the relevant detection under a documented time/correlation policy.
7. Coverage counts only evidence that meets the verification policy.
8. Artifacts are archived and checked for integrity.
9. The CI gate returns `PASS`, `FAIL`, or `INCONCLUSIVE` based on explicit policy and available evidence.

## 6. Deployment modes

- **Local simulation:** intended for development, UI/API workflow checks, and demonstration. It is not proof of live attack or sensor behavior.
- **Integrated test environment:** uses real external services and a disposable isolated cluster. This mode must be established and verified before live capability claims.
- **Production-like deployment:** requires security review, hardened infrastructure, secrets management, monitoring, backups, operational procedures, and explicit authorization boundaries. It is not established by the supplied evaluation.
