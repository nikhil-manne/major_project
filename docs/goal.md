# Project Goal and Scope

## Goal

Build a cyber-range platform that connects authorized attack emulation, defensive detection, security-event normalization, session replay, MITRE ATT&CK validation, readiness scoring, and CI/CD security decisions in one workflow.

The long-term objective is to help a team answer: **“When a known attack technique is exercised against an isolated build or lab, what evidence was produced, was it detected, and what should happen before release?”**

## Current project scope

The current prototype focuses on:

- A FastAPI backend and React dashboard source.
- Local authentication and role-based API checks.
- Lab upload policy screening.
- Simulated attack scenarios and rule evaluation.
- Local event persistence and replay of stored events.
- Coverage, heuristic score, and CI-gate behaviour that explicitly distinguish simulation from live evidence.
- A deterministic Copilot fallback for local demonstration.

## Out of current verified scope

The supplied evaluation does not establish a production-ready cyber range. Live Kubernetes isolation, hardened image builds, real attack execution, sensor/packet capture, external data services, production model retrieval, and a successful frontend production build require additional verification.

## Safety boundaries

- Execute attack scenarios only against explicitly authorized targets.
- Treat simulation output as demonstration data, not evidence of a real exploit or detection.
- Do not build or launch untrusted uploaded Dockerfiles in a shared environment until an isolated build-and-runtime security design is implemented and tested.
- Do not expose local development authentication or development-only infrastructure settings to untrusted networks.

## Success criteria

The project reaches its intended target when a repeatable end-to-end test can create an isolated lab, execute an approved scenario, ingest real telemetry, link a detection to the attack evidence, produce defensible ATT&CK coverage, archive/replay the session, and enforce a documented CI decision. Every stage must retain traceable test evidence.
