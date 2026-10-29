> **Implementation-status note:** this document describes the project's intended long-term goal. It does not establish that those capabilities are implemented or verified. Check the repository `README.md` and sandbox evaluation report for the current verified scope.

# Project Goal

## Project Name
Unified AI-Powered Cyber Range & Security Validation Platform
*(Adversary Emulation, Adaptive Defense Validation, Threat Hunting & MITRE ATT&CK Coverage Analysis)*

## One-Line Goal
Build a single enterprise platform that lets Red Team, Blue Team, and SOC analysts **attack, defend, analyze, replay, validate, and report** on the security of software — both **before release** (in an isolated sandbox) and **after release** (as a production-grade SIEM) — with an AI Security Copilot assisting every role, instead of using disconnected, manual tools for each function.

---

## The Problem We're Solving
Today, when a company ships a new feature, testing its security requires multiple disconnected steps run by different teams with different tools:
- Red team manually attacks a test environment using one set of tools.
- Blue team manually monitors for those attacks using a separate set of tools.
- SOC analysts review production logs in a completely different system (e.g., a SIEM like Microsoft Sentinel).
- Mapping what was attacked to what was actually detected (MITRE ATT&CK coverage) is done manually, often in spreadsheets.
- There is no easy way to "replay" a past attack to test a newly written detection rule.
- Pre-release security testing and production monitoring are run by different teams with **zero shared data** between them.

This fragmentation causes detection gaps, slow incident response, and no continuous feedback loop between "did we catch this in testing" and "are we catching this live in production."

---

## Our Solution
A **unified platform** where all security functions share one engine and one data model:

| Function | What it means here |
|---|---|
| **Attack** | Red team (manual or automated BAS playbooks) attacks a target inside an isolated sandbox |
| **Defend** | Blue team's detection rules (Sigma-based) run in parallel, trying to catch each attack |
| **Analyze** | SOC dashboard provides live alert triage, case management, and threat hunting over the same data |
| **Replay** | Every recorded attack (terminal actions, network traffic, structured events) can be re-run later to test new detection rules — like a regression test suite for security |
| **Validate** | Automatically cross-references attacks run vs. techniques detected, producing a live MITRE ATT&CK coverage heatmap (no manual spreadsheet mapping) |
| **Report** | A Security Readiness Score rolls up detection coverage, response time, and incident resolution into a single trackable metric |

An **AI Security Copilot** sits across all roles: explaining alerts and suggesting fixes to Blue Team, suggesting next attack techniques to Red Team, and summarizing incidents for SOC — all from the same underlying data, scoped by role and tenant.

---

## Two Operating Modes, One Engine

### Mode 1 — Pre-Release Security Gate
When a new build/feature is ready to ship:
1. An isolated, disposable sandbox is spun up automatically.
2. The new build is deployed into it.
3. Red team (or automated attack scenarios relevant to the code change) attacks it.
4. Blue team's detection rules try to catch each attack in real time.
5. The system computes a readiness score and MITRE coverage report for this specific build.
6. The sandbox is destroyed; the full session (terminal recording, network capture, and event timeline) is archived for later **replay**.
7. This can act as an automated **CI/CD security gate** — blocking a release if coverage drops or a previously-caught technique goes undetected.

### Mode 2 — Production Monitoring (SIEM-like)
The same detection engine, same MITRE mapping, and same AI copilot now run passively against live production logs — functioning like an enterprise SIEM (e.g., Microsoft Sentinel), but with one advantage: because the exact same build was already tested in Mode 1, the platform knows in advance which attack techniques its production detections can reliably catch, and can trace a live incident back to its pre-release test history.

---

## Why This Is Different From Existing SIEM Tools (e.g., Microsoft Sentinel)
Traditional SIEMs are **passive** — they only analyze logs after an attack has already happened elsewhere. They have no native attack simulation, no replay-as-regression-testing, and no automatic MITRE coverage validation; these are bolted on from separate third-party tools with no shared data model.

Our platform's core differentiator: **Attack, Defend, Replay, and Validate all read and write to one normalized event schema**, so validation becomes a query instead of a manual spreadsheet exercise, and a production incident can be traced directly back to how (and whether) it was caught during pre-release testing.

---

## Core Technical Components
- **Identity & RBAC:** Keycloak (role-based access: Red Team, Blue Team, SOC, Admin)
- **Sandbox isolation:** Kubernetes namespace-per-session with NetworkPolicy enforcement, created/destroyed on demand
- **Event backbone:** Kafka + a single normalized event schema shared by every module
- **Storage:** PostgreSQL (metadata/rules) + OpenSearch (logs/events/search)
- **Attack engine:** Scripted/automated attack scenarios mapped to MITRE ATT&CK techniques
- **Detection engine:** Sigma rules compiled and matched against live event data (Falco for host/runtime, Suricata/Zeek for network)
- **Replay engine:** Re-emits recorded terminal sessions, packet captures, and structured events on a synchronized timeline
- **Validation engine:** Auto-computed MITRE ATT&CK coverage heatmap
- **Scoring engine:** Weighted Security Readiness Score
- **AI Copilot:** RAG-based assistant (role- and tenant-aware) for alert explanation, rule generation, attack-path suggestion, and incident summarization
- **Dashboards:** Role-specific web UIs for Red Team, Blue Team, SOC, and Admin

---

## Project Scope (Academic/Major Project Level)
Given this is a major project with a limited timeline, the goal is to build a **working, demoable closed loop**:
> Upload a build → sandbox spins up → red team attacks it → blue team detects it → MITRE coverage is computed → readiness score is generated → AI copilot explains what happened → the full session can be replayed.

This proves the core unifying idea end-to-end, rather than building every enterprise feature at full depth.

---

## Success Criteria
- [ ] A new build can be submitted and automatically deployed into an isolated sandbox
- [ ] Red team can execute at least a handful of real attack scenarios against the sandboxed target
- [ ] Blue team's detection rules catch at least some of those attacks in real time
- [ ] MITRE ATT&CK coverage is computed automatically from attack vs. detection data (no manual mapping)
- [ ] A full session (attacks + detections) can be replayed on a timeline after the fact
- [ ] The AI Copilot can explain at least one alert and suggest at least one detection rule in plain language
- [ ] A Security Readiness Score is generated per session/build
