> **Illustrative demo guide — not a verified execution report.** Any sample session IDs, tenant IDs, output, counts, screenshots, percentages, and example rules in this document are placeholders unless explicitly marked as captured from a repeatable live test. The current local evaluation runs in simulation mode by default; simulated results must not be reported as real attack, detection, packet-capture, or production-readiness evidence. See `README.md` and `scripts/evaluate_local.py` for current verification status.

# 🛡️ Cyber Range & Security Validation Platform v2.0
## Comprehensive End-to-End User Guide & Demonstration Manual

> **Adversary Emulation, Adaptive Defense Validation, Threat Hunting, Session Replay & MITRE ATT&CK Coverage**

---

## 📑 Table of Contents
1. [Platform Overview & Core Philosophy](#1-platform-overview--core-philosophy)
2. [Quick Start & Startup Sequence](#2-quick-start--startup-sequence)
3. [Global Navigation Bar & Controls](#3-global-navigation-bar--controls)
4. [Page-by-Page Feature & Button Reference](#4-page-by-page-feature--button-reference)
   - [🧪 1. Labs Overview (`LabsOverview.jsx`)](#-1-labs-overview-labsoverviewjsx)
   - [⚔️ 2. Red Team Offensive Console (`RedTeamConsole.jsx`)](#️-2-red-team-offensive-console-redteamconsolejsx)
   - [🛡️ 3. Blue Team Defense Hub (`BlueTeamHub.jsx`)](#️-3-blue-team-defense-hub-blueteamhubjsx)
   - [🎯 4. MITRE ATT&CK Matrix & Validation Engine (`MitreNavigatorMatrix.jsx`)](#-4-mitre-attck-matrix--validation-engine-mitrenavigatormatrixjsx)
   - [📊 5. SOC Analyst Desk (`SocAnalystDesk.jsx`)](#-5-soc-analyst-desk-socanalystdeskjsx)
   - [⏪ 6. Replay Studio (`ReplayStudio.jsx`)](#-6-replay-studio-replaystudiojsx)
   - [🚪 7. Pre-Release CI/CD Security Gate (`CiGateView.jsx`)](#-7-pre-release-cicd-security-gate-cigateviewjsx)
   - [⚙️ 8. Admin & Infrastructure Monitor (`AdminOverview.jsx`)](#️-8-admin--infrastructure-monitor-adminoverviewjsx)
   - [🤖 9. AI Security Copilot (`CopilotDrawer.jsx`)](#-9-ai-security-copilot-copilotdrawerjsx)
5. [End-to-End Walkthroughs (Tutorials)](#5-end-to-end-walkthroughs-tutorials)
   - [Walkthrough A: Closing a Detection Gap (From Red to Green)](#walkthrough-a-closing-a-detection-gap-from-red-to-green)
   - [Walkthrough B: Executing Automated Playbooks & SOC Triage](#walkthrough-b-executing-automated-playbooks--soc-triage)
   - [Walkthrough C: Using Deterministic Replay for Regression Testing](#walkthrough-c-using-deterministic-replay-for-regression-testing)
6. [Architecture & Telemetry Pipeline](#6-architecture--telemetry-pipeline)
7. [Troubleshooting & Frequently Asked Questions](#7-troubleshooting--frequently-asked-questions)

---

## 1. Platform Overview & Core Philosophy

### The Problem with Traditional SIEMs (Declared Intent)
Traditional SIEM solutions (e.g., Microsoft Sentinel, Splunk) measure security posture based on **Declared Intent**:
* If an analyst writes or tags a rule with `attack.t1190` (SQL Injection), the SIEM marks that technique as "Covered" on a spreadsheet or dashboard.
* **The Reality:** In reality, the rule might be misconfigured, the sensor might not be logging that endpoint, or a minor payload variation will bypass it. You don't actually know if your defenses work until a breach happens.

### The Solution: Proven Outcome-Based Validation
This platform unites **Red Team (Offensive)**, **Blue Team (Defensive)**, and **SOC Analysts (Operational)** on a single shared event stream:
* **Untested (Slate):** No adversary emulation has been executed for this technique in this session.
* **Detection Gap (Crimson Red):** An attack technique was launched, but Blue Team sensors fired **0 matching detection alerts** within the evaluation time window.
* **Proven Covered (Emerald Green):** An attack was executed AND a detection rule matched it within the time window.

```
┌────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│ Red Team Probe │ ───► │ Normalized Event Stream │ ◄─── │ Blue Team Sigma Sensors │
└────────────────┘      └────────────┬────────────┘      └─────────────────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │ MITRE Validation Engine │
                        │   Attack + Detection    │
                        └────────────┬────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
        [ MATCH WITHIN 120s ]                   [ 0 DETECTIONS FIRED ]
        Emerald Green (COVERED)                 Crimson Red (GAP)
```

---

## 2. Quick Start & Startup Sequence

### Starting the Platform
Double-click [`run.bat`](file:///c:/Major/v2/run.bat) from the project root (or run in PowerShell/CMD):
```cmd
run.bat
```

What `run.bat` does automatically:
1. **Verifies Environment:** Checks Python 3.10+ and Node.js 18+.
2. **Dependencies:** Auto-installs `requirements.txt` and `npm install` for the frontend.
3. **Infrastructure Detection:**
   * If Docker is active: Starts PostgreSQL, Kafka, MinIO, and OpenSearch via `docker compose up -d`.
   * If Docker is not running: Automatically switches to **Standalone Resilient Mode** (SQLite fallback `cyberrange.db`, local disk archive mirror, and in-memory streaming channel).
4. **Launches Backend:** Starts the FastAPI API Server on `http://localhost:8000`.
5. **Launches Frontend:** Starts the Vite React dashboard on `http://localhost:3000`.
6. **Opens Browser:** Automatically navigates your default browser to `http://localhost:3000`.

### Stopping the Platform
Double-click [`stop.bat`](file:///c:/Major/v2/stop.bat) to terminate all server processes cleanly.

---

## 3. Global Navigation Bar & Controls

Located at the very top of the interface:

```
[ ⚔️ CYBER RANGE v2.0 ] [Labs] [Red Team] [Blue Team] [MITRE Matrix] [SOC Desk] [Replay] [CI Gate] [Admin]  [Sandbox | Replay] [⚡ Seed Full Demo] [🤖 Copilot]
```

### Navigation Items:
1. **Role Tabs:** Click any tab to switch between the specialized interfaces:
   * **Labs Overview (`🧪`):** Dockerfile upload, security scanning, sandbox lifecycle.
   * **Red Team (`⚔️`):** Playbook launcher, interactive web terminal (`ttyd`), live payload execution.
   * **Blue Team (`🛡️`):** Real-time alert feed, interactive Sigma rule compiler with pySigma verification.
   * **MITRE Matrix (`🎯`):** Real-time heatmap of covered vs. gap techniques with scope filtering.
   * **SOC Desk (`📊`):** Cyber Readiness Scorecard (0-100), incident triage queue, threat hunting.
   * **Replay Studio (`⏪`):** Time-scrubbed synchronized playback of recorded sessions.
   * **CI Gate (`🚪`):** Automated security validation gate for CI/CD pipelines with pass/fail reports.
   * **Admin (`⚙️`):** Tenant switcher, resource quotas, and system health status.

2. **Mode Switcher (`Sandbox` vs `Replay`):**
   * **Sandbox:** Executes live commands and automated attacks against active targets.
   * **Replay:** Freezes live execution and routes event feeds from recorded MinIO session archives.

3. **`⚡ Seed Full Demo` Button:**
   * **What it does:** Instantly provisions an end-to-end cyber range session (`sess-demo-xxx`), runs 3 multi-vector attacks, evaluates detection rules, computes a readiness score, and populates the timeline.
   * **Use case:** Perfect for presentations, demos, or testing platform analytics without manually executing commands.

4. **`🤖 AI Copilot` Button:**
   * Opens the collapsible AI assistant drawer from the right edge of the screen.

---

## 4. Page-by-Page Feature & Button Reference

---

### 🧪 1. Labs Overview (`LabsOverview.jsx`)
The entry point for provisioning target software containers to test.

```
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────┐
│ 📦 Upload Target Dockerfile or Compose       │ │ 🖥️ Active Isolated Sandboxes                 │
│ [ Drop Dockerfile or click preset ]          │ │                                              │
│ [ 🛡️ Scan Image Safety ] [ 🚀 Launch Sandbox ]│ │ • Session: sess-722a3d47  Status: ACTIVE     │
│ Safety Report: Trivy (0 High) Hadolint (Pass)│ │   CPU: 12%  RAM: 180MB  TTL: 28m left        │
│                                              │ │   [ Enter Red Terminal ] [ 🗑️ Destroy ]     │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────┘
```

#### Sections & Controls:
* **Upload Card:**
  * **Textarea / File Drop:** Paste a Dockerfile or `docker-compose.yml` defining the application under test.
  * **Preset Selector:** Choose pre-configured targets (e.g., `vulnerable-struts-app:2.3.31`, `alpine-debug`, `juice-shop`).
  * **Button: `🛡️ Scan Image Safety`:** Triggers static security scanning (Hadolint Dockerfile linter and Trivy vulnerability scanner).
  * **Button: `🚀 Launch Sandbox`:** Provisions an isolated Kubernetes namespace (`sandbox-sess-xxxx`) with default-deny NetworkPolicies, container security context, and monitoring sidecars (Falco + Suricata).
* **Active Sandboxes Grid:**
  * Displays running sessions, elapsed time, memory usage, and sandbox status.
  * **Button: `Enter Red Terminal`:** Directs you to the Red Team Console scoped to this specific session.
  * **Button: `🗑️ Destroy`:** Teardown container, captures logs, exports the session archive, and frees cluster resources.

---

### ⚔️ 2. Red Team Offensive Console (`RedTeamConsole.jsx`)
The adversary emulation command center.

```
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────┐
│ ⚔️ Adversary Emulation Playbooks             │ │ 📡 Raw Attack Events Stream                  │
│ [ scn-sqli-04: SQL Injection (T1190) ▼ ]     │ │                                              │
│ [ Execute Attack ]                           │ │ [ATTACK] 17:53:22 curl -i -s "http://..."    │
├──────────────────────────────────────────────┤ │ Technique: T1190 | Severity: HIGH            │
│ 🖥️ ttyd: redteam@toolbox-pod (sess-active)   │ │                                              │
│ redteam@toolbox:~$ curl -i -s "http://..."   │ │ [ATTACK] 17:52:10 nmap -sS -p 80,445 target  │
│ [Technique Tagged: T1190]                    │ │ Technique: T1046 | Severity: MEDIUM          │
│ redteam@toolbox:~$ [                        ]│ │                                              │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────┘
```

#### Sections & Controls:
* **Playbook Launcher:**
  * **Dropdown: `Select Scenario`:** Choose from curated MITRE ATT&CK adversary playbooks:
    * `scn-portscan-01`: Network Service Discovery (`T1046`)
    * `scn-smb-02`: Remote Exploitation via SMB (`T1210`)
    * `scn-sqli-04`: Exploit Public-Facing Application via SQLi (`T1190`)
    * `scn-rce-05`: Command and Scripting Interpreter (`T1059`)
    * `scn-brute-03`: Valid Accounts Brute-Force (`T1078`)
  * **Button: `Execute Attack`:** Spawns an automated adversary runner that sends requests, records terminal stdout via asciinema, and emits structured events into the Kafka `raw.attack` topic.
* **Interactive Web Terminal (`ttyd`):**
  * Emulates an in-pod Linux terminal scoped to the sandbox network namespace.
  * **Prompt:** Type real commands directly:
    * Port scan: `nmap -sS -p 80,445 target-pod`
    * Metasploit probe: `msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; run"`
    * SQL injection probe: `curl -i -s "http://target-sandbox:8080/api/users?id=1'"`
    * Blind boolean probe: `curl -s "http://target-sandbox:8080/api/products?category=app'+OR+1=1--"`
  * **Automatic Technique Inferencing:** The terminal automatically tags commands with their corresponding MITRE technique (`[Technique Tagged: T1190]`) and tactics.
* **Raw Attack Events Stream (Right Column):**
  * Displays every attack event published in chronological order with execution timestamps and parameter payloads.

---

### 🛡️ 3. Blue Team Defense Hub (`BlueTeamHub.jsx`)
The defensive engineering and detection engineering workspace.

```
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────┐
│ 🛡️ Live Detection Alerts Feed                │ │ 📝 Sigma Rule Compiler                      │
│ [ Evaluate Active Rules ]                    │ │ Active Rules: [T1190] [T1046] [T1210] [+]   │
├──────────────────────────────────────────────┤ ├──────────────────────────────────────────────┤
│ [DETECTED] rule:HTTP Parameter Injection     │ │ title: Exploit Public-Facing Application     │
│ Severity: HIGH | MITRE T1190 | TA0001        │ │ id: rule-t1190-high-precision                │
│ Sensor: web_waf_suricata | Time: 17:53:23    │ │ detection:                                   │
│ trigger: curl -i -s "http://...id=1'"        │ │   selection: action|contains: ["id=1'"]      │
│                                              │ │ [ Verify Syntax ]  [ Save & Deploy Rule ]    │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────┘
```

#### Sections & Controls:
* **Live Detection Alerts Feed (Left Column):**
  * Shows all security alerts triggered by defensive sensors.
  * **Alert Card Details:**
    * `DETECTED` badge
    * Severity tag (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
    * Rule Name & MITRE Technique ID (`MITRE T1190`)
    * Telemetry source (`web_waf_suricata`, `falco_ebpf`, etc.)
    * Raw triggering command or payload snippet
  * **Button: `Evaluate Active Rules`:**
    * Immediately scans recent session events against all active compiled Sigma rules in memory and outputs newly triggered alerts.
  * **Empty State Guidance:** Explains that if manual attacks bypassed detection, 0 alerts will show (this is a Detection Gap), directing you to the MITRE Matrix.
* **Sigma Rule Compiler (Right Column):**
  * **Rule Selector Pills:** Click pills like `T1046`, `T1190`, `T1210` to view and edit pre-loaded rules.
  * **YAML Code Editor:** Write or paste Sigma detection rules using standard syntax (`logsource`, `detection`, `selection`, `condition`).
  * **Button: `Verify Syntax`:** Runs the rule through the `SigmaEngine` validator to ensure condition blocks, fields, and YAML syntax are valid.
  * **Button: `Save & Deploy Rule`:**
    * Compiles the rule into an OpenSearch DSL query.
    * Persists the rule in PostgreSQL (`sigma_rules` table).
    * Registers the rule in memory for the real-time event evaluator.

---

### 🎯 4. MITRE ATT&CK Matrix & Validation Engine (`MitreNavigatorMatrix.jsx`)
The core validation interface showing **Proven Outcome** coverage.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ 🎯 MITRE ATT&CK Matrix & Security Validation                                                 │
│ Outcome-Based Coverage: Proves defense only when an attack was executed and actually caught. │
│ Scope: [ Active Session (sess-active) ▼ ]   [ ⬇ Export Navigator v4.5 Layer ] [ Refresh ]    │
├──────────────────────────────┬──────────────────────────────┬────────────────────────────────┤
│ Validation Coverage: 50.0%   │ Proven Covered: 1 (Green)    │ Detection Gaps: 1 (Red)        │
└──────────────────────────────┴──────────────────────────────┴────────────────────────────────┘

┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Reconnaissance  │ │ Initial Access  │ │ Execution       │ │ Lateral Move    │ │ Discovery       │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│ T1595           │ │ T1190           │ │ T1059           │ │ T1210           │ │ T1046           │
│ [ UNTESTED ]    │ │ [ GAP ] (Red)   │ │ [ UNTESTED ]    │ │ [ COVERED ](Grn)│ │ [ COVERED ](Grn)│
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
```

#### Sections & Controls:
* **Summary Counters:**
  * **Validation Coverage %:** `Covered / (Covered + Gaps) * 100`
  * **Proven Covered:** Number of techniques where an attack was launched AND detected within 120 seconds.
  * **Detection Gaps:** Number of techniques where an attack succeeded but 0 alerts fired.
  * **Untested Techniques:** Techniques not yet exercised in this session.
* **Controls Bar:**
  * **Scope Dropdown:**
    * `Active Session (sess-active)`: Filters coverage strictly to the current session.
    * `All Sessions (Aggregate)`: Combines events across all sessions to show global organizational coverage.
  * **Button: `⬇ Export Navigator v4.5 Layer`:**
    * Generates and downloads an official MITRE ATT&CK Navigator v4.5 JSON layer file. You can drag and drop this file into [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)!
  * **Button: `Refresh Heatmap`:** Re-queries `/api/v1/validation/coverage` to redraw colors.
* **Interactive Matrix Grid:**
  * Organized by MITRE Tactics (Reconnaissance, Initial Access, Execution, Persistence, Lateral Movement, Discovery, Impact).
  * **Color Codes:**
    * 🟩 **Emerald Green (Covered):** Attack detected.
    * 🟥 **Crimson Red (Gap):** Attack executed, no detection.
    * ⬜ **Slate Gray (Untested):** No attack executed yet.
* **Technique Detail Modal (Click any technique box):**
  * Displays technique description, number of attacks executed, number of detections fired, and latency in seconds.
  * **Button: `🤖 Request AI Copilot Rule`:** Pre-loads the AI Copilot with a prompt specifically asking for a Sigma rule to close this exact detection gap!

---

### 📊 5. SOC Analyst Desk (`SocAnalystDesk.jsx`)
The operational interface for SOC monitoring, readiness scoring, and threat hunting.

```
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────┐
│ 🛡️ Cyber Readiness Scorecard                 │ │ 🔍 Threat Hunting Console (OpenSearch)       │
│                [ 78 / 100 ]                  │ │ [ action:curl AND mitre_technique:T1190   ] │
│ Coverage: 60% | Avg Latency: 1.4s | Incs: 1  │ │ [ Run Hunt Query ]                           │
├──────────────────────────────────────────────┤ ├──────────────────────────────────────────────┤
│ 🚨 Security Incidents Queue                  │ │ Matching Events (1):                         │
│ • INC-8a12b: T1190 Exploit Attempt (HIGH)    │ │ • 17:53:22 | web_terminal | curl -i -s ...   │
│   Status: [ Investigating ▼ ] [ Update ]     │ │   Session: sess-active | Actor: red1         │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────┘
```

#### Sections & Controls:
* **Cyber Readiness Scorecard:**
  * **Score Formula:** 
    $$\text{Score} = (0.50 \times \text{Coverage}) + (0.30 \times \text{LatencyScore}) - (0.20 \times \text{UnresolvedPenalty})$$
  * Gives a realistic 0–100 posture score evaluating both coverage depth and analyst response speed.
* **Incident Triage Queue:**
  * List of actionable security incidents generated from detection alerts.
  * **Status Dropdown:** Update lifecycle state between `Open` ➔ `Investigating` ➔ `Contained` ➔ `Resolved` ➔ `False Positive`.
* **Threat Hunting Console:**
  * **Search Query Bar:** Search across all indexed raw and normalized events in OpenSearch using Lucene/keyword queries (e.g., `source_type:attack AND action:curl` or `status:succeeded`).
  * **Button: `Run Hunt Query`:** Returns matching event records instantly with full JSON payload expansion.

---

### ⏪ 6. Replay Studio (`ReplayStudio.jsx`)
The digital black-box flight recorder and regression testing workbench.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ ⏪ Deterministic Attack & Telemetry Replay Engine                                            │
│ Replay Session: [ sess-3383ca96 (vulnerable-struts-app) ▼ ]   Speed: [ 1x ] [ 2x ] [ 4x ]    │
│ [ ▶ Play ] [ ⏸ Pause ] [ ⏭ Step Forward ]   Timeline: 00:14 / 01:30 [═══════●──────────────] │
├──────────────────────────────┬──────────────────────────────┬────────────────────────────────┤
│ 💻 Terminal Stream (.cast)   │ 🌐 Network Packets (.pcap)   │ 📂 Host Syscalls (Falco)       │
│ $ nmap -sS -p 80,445 10.244  │ HTTP GET /api/users?id=1'    │ sys_clone pid=1042 /bin/bash   │
│ PORT 80/tcp open http        │ Suricata SID: 2014022        │ execve /bin/sh (suspicious)    │
└──────────────────────────────┴──────────────────────────────┴────────────────────────────────┘
```

#### Sections & Controls:
* **Archive Selector Dropdown:** Loads archived sessions stored in MinIO S3 (or local disk fallback). Each archive contains:
  * `manifest.json`: Session metadata, image tag, and isolation profile.
  * `events.jsonl`: Complete synchronized normalized event stream.
  * `terminal.cast`: Asciinema v2 multi-channel terminal recording.
  * `network.pcap`: Packet capture recording.
* **Synchronized Playback Controls:**
  * **Button: `▶ Play` / `⏸ Pause`:** Starts and pauses time-accurate event playback.
  * **Button: `⏭ Step Forward`:** Advances to the next sequential event.
  * **Speed Buttons (`1x`, `2x`, `4x`):** Increases simulation playback speed.
  * **Timeline Scrubber Slider:** Drag the slider backward or forward in time; all streams update simultaneously.
* **Three-Stream View:**
  * **Terminal Stream:** Terminal commands as they were typed by the attacker.
  * **Network Stream:** Ingress/egress HTTP requests and packet anomalies.
  * **Host Syscalls:** Kernel events, process execution, and privilege escalation probes captured by eBPF.

---

### 🚪 7. Pre-Release CI/CD Security Gate (`CiGateView.jsx`)
The automated security gate for GitHub Actions, GitLab CI, or Jenkins.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ 🚪 Pre-Release CI/CD Security Validation Gate                                                │
│ Commit: sha-e921bf3   Branch: main   Image: target-app:bld-099   Gate Policy: Strict         │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Gate Status: [ ❌ FAILED ] (Coverage: 50% < Threshold: 80% | Unresolved Gaps: 1)              │
│                                                                                              │
│ Gate Criteria Checklist:                                                                     │
│ • Minimum MITRE Coverage >= 80%:       ❌ FAILED (50.0%)                                     │
│ • Zero Critical Gaps in Initial Access: ❌ FAILED (1 Gap in T1190)                            │
│ • Zero Rootless Security Violations:   ✅ PASSED                                             │
│                                                                                              │
│ [ 📄 Export Build Audit Report (Markdown) ]   [ 🔄 Re-evaluate Pipeline ]                    │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Sections & Controls:
* **Gate Verdict Badge:** Displays `PASSED` (green) or `FAILED` (red) based on organizational security policy.
* **Button: `Export Build Audit Report`:** Generates a formatted markdown compliance document to be attached as a PR comment or CI artifact.
* **Button: `Re-evaluate Pipeline`:** Reruns validation against the latest build sandbox session.

---

### ⚙️ 8. Admin & Infrastructure Monitor (`AdminOverview.jsx`)
Administrative control and infrastructure health monitor.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ ⚙️ Infrastructure Backbone Health & Multi-Tenant Control                                      │
├──────────────────────────────┬──────────────────────────────┬────────────────────────────────┤
│ PostgreSQL: Connected        │ Apache Kafka: Connected      │ Kubernetes Cluster: Connected  │
│ MinIO S3: Storage Active     │ OpenSearch Sink: Connected   │ Ingestion Pipeline: Healthy    │
├──────────────────────────────┴──────────────────────────────┴────────────────────────────────┤
│ Active Tenant: [ Default Enterprise (org-123) ▼ ]   Role Override: [ admin1 ▼ ]             │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Sections & Controls:
* **Infrastructure Health Grid:** Displays real-time status badges for PostgreSQL, Kafka, Kubernetes, MinIO S3, and OpenSearch.
* **Tenant Switcher:** Easily toggle between multi-tenant scopes (`org-123` vs `org-999`) to test tenant data isolation.

---

### 🤖 9. AI Security Copilot (`CopilotDrawer.jsx`)
The role-aware AI security assistant.

```
┌──────────────────────────────────────────────┐
│ 🤖 AI Security Copilot                       │
│ Role: [ Blue Team Defense ▼ ]                │
├──────────────────────────────────────────────┤
│ Quick Prompts:                               │
│ [ Explain Alert ]   [ Draft Sigma Rule ]     │
│ [ Suggest Next Attack ] [ Summarize Session ]│
├──────────────────────────────────────────────┤
│ > Draft a Sigma detection rule for T1190...  │
│                                              │
│ Copilot:                                     │
│ Here is a high-precision rule for T1190:     │
│ ```yaml                                      │
│ title: Exploit Public-Facing Application...  │
│ ```                                          │
│ [ Copy Rule to Clipboard ]                   │
└──────────────────────────────────────────────┘
```

#### Features:
* **Collapsible Drawer:** Accessible from anywhere on the platform via the `🤖 Copilot` button.
* **Role-Aware Context:** Adapts reasoning based on whether you are acting as Red Team, Blue Team, or SOC Analyst.
* **One-Click Quick Prompts:**
  1. **Explain Alert:** Translates cryptographic or technical payload signatures into plain English threat context.
  2. **Draft Sigma Rule:** Synthesizes ready-to-deploy Sigma rules tailored to detected attack patterns.
  3. **Suggest Next Attack:** Recommends subsequent MITRE techniques based on reconnaissance output.
  4. **Summarize Session:** Drafts executive debriefings summarizing attacks, caught alerts, and remaining gaps.

---

## 5. End-to-End Walkthroughs (Tutorials)

---

### Walkthrough A: Closing a Detection Gap (From Red to Green)
*Goal: Emulate an adversary SQL injection exploit, observe the detection gap in the MITRE matrix, deploy a Blue Team Sigma rule, and verify coverage turns green.*

1. **Step 1: Launch the Platform**
   * Double-click `run.bat` and open `http://localhost:3000`.
2. **Step 2: Execute an Adversary Probe (Red Team)**
   * Click on the **Red Team** tab.
   * In the web terminal at the bottom, type:
     ```bash
     curl -i -s "http://target-sandbox:8080/api/users?id=1'"
     ```
   * Press **Enter**. You will see:
     ```text
     [*] HTTP request dispatched to target: curl -i -s "http://target-sandbox:8080/api/users?id=1'"
     [+] SQL injection payload delivered to application parameter
     [Technique Tagged: T1190]
     ```
3. **Step 3: Observe the Detection Gap (MITRE Matrix)**
   * Click on the **MITRE Matrix** tab.
   * Under the **Initial Access** column, look at **T1190 (Exploit Public-Facing Application)**.
   * It is **Crimson Red (`[ GAP ]`)**! The top counter will show `Detection Gaps: 1`.
   * Click on the red **T1190** box to inspect the details: `Attacks: 1 | Detections: 0`.
4. **Step 4: Generate a Defense Rule (AI Copilot / Blue Team)**
   * Click **"🤖 Request AI Copilot Rule"** inside the modal (or copy the rule below):
     ```yaml
     title: Exploit Public-Facing Application - HTTP Parameter Injection
     id: rule-t1190-high-precision
     status: test
     description: Detects SQL injection probes targeting public HTTP API parameters (T1190).
     tags:
       - attack.ta0001
       - attack.t1190
     logsource:
       category: network
       product: web_waf_suricata
     detection:
       selection:
         action|contains:
           - "id=1'"
           - "+or+1=1"
           - "or 1=1"
           - "api/users?id="
       condition: selection
     level: high
     ```
5. **Step 5: Deploy the Rule (Blue Team Hub)**
   * Click on the **Blue Team** tab.
   * In the **Sigma Rule Compiler** on the right, paste the YAML above into the editor.
   * Click **Verify Syntax** → You will see `✔ Validated via pySigma`.
   * Click **Save & Deploy Rule**.
6. **Step 6: Evaluate Detections**
   * On the left side of Blue Team, click **"Evaluate Active Rules"**.
   * A new alert card will immediately appear in the Live Alerts Feed:
     ```text
     [DETECTED] rule:Exploit Public-Facing Application - HTTP Parameter Injection matched
     Severity: HIGH | MITRE T1190 | TA0001
     ```
7. **Step 7: Confirm Proven Coverage**
   * Return to the **MITRE Matrix** tab.
   * **T1190** has now turned **Emerald Green (`[ COVERED ]`)**!
   * The counter shows `Proven Covered: 1`, `Detection Gaps: 0`, `Validation Coverage: 100%`.

---

### Walkthrough B: Executing Automated Playbooks & SOC Triage
*Goal: Run a scripted multi-stage attack and triage incidents on the SOC Desk.*

1. In **Red Team**, select `scn-portscan-01: Network Service Discovery (T1046)`.
2. Click **Execute Attack**. The terminal will run Nmap probes against open ports.
3. Switch to **Blue Team** and click **Evaluate Active Rules**; an alert for port scan activity appears.
4. Switch to **SOC Desk**:
   * Observe the **Cyber Readiness Scorecard**.
   * Look at the **Incidents Queue**; a new incident `INC-xxxx (T1046 Reconnaissance)` is open.
   * Change its status from `Open` to `Investigating` and add analyst notes.
5. In the **Threat Hunting Console**, enter `action:nmap` and click **Run Hunt Query** to inspect raw packet parameters.

---

### Walkthrough C: Using Deterministic Replay for Regression Testing
*Goal: Replay a previously recorded attack to verify if a new detection rule catches it without re-running offensive tools.*

1. Click on the **Replay** tab.
2. Select any archived session from the dropdown (e.g., `sess-3383ca96`).
3. Click **▶ Play**.
4. Observe the terminal cast typing commands and the network packet feed scrolling in exact timestamp synchronization.
5. Drag the timeline slider to scrub back to the exact second an exploit payload was delivered.

---

## 6. Architecture & Telemetry Pipeline

```
[Red Team Web Terminal]  ──► [Kafka: raw.attack]   ──┐
[Falco eBPF Daemon]       ──► [Kafka: raw.host]     ──┼─► [Ingestion Normalizer] ─► [Kafka: normalized.events]
[Suricata NIDS Sidecar]   ──► [Kafka: raw.network]  ──┘              │
                                                                     ▼
                                                          [OpenSearch Event Sink]
                                                                     │
                                             ┌───────────────────────┴───────────────────────┐
                                             ▼                                               ▼
                                  [Blue Team Detection Engine]                   [MITRE Validation Engine]
                                  Matches pySigma Rules                          Correlates Attacks & Detections
                                             │                                               │
                                             ▼                                               ▼
                                  [Live Security Alerts]                         [Coverage Heatmap (Green/Red)]
```

### The Normalized Event Schema (`NormalizedEvent`):
Every event in the platform adheres to this schema:
```json
{
  "event_id": "b3e21894-...",
  "tenant_id": "org-123",
  "session_id": "sess-active",
  "timestamp": "2026-10-24T00:15:20Z",
  "source_type": "attack | detection | network | host | soc_action",
  "source_name": "web_terminal | suricata | falco | sigma_rule",
  "actor": "red1 | analyst | system",
  "action": "curl -i -s http://target:8080/api/users?id=1'",
  "mitre_tactic": "TA0001",
  "mitre_technique": "T1190",
  "severity": "high",
  "outcome": "succeeded | detected | blocked | undetected",
  "raw_payload": { ... }
}
```

---

## 7. Troubleshooting & Frequently Asked Questions

### Q1: Why did my command say `[Technique Tagged: T1059]` instead of `T1190`?

* **Explanation:** Generic shell commands default to `T1059` (Command and Scripting Interpreter).
* **Fix:** When launching web exploits or SQL injection probes, include HTTP or parameter keywords (such as `curl`, `http://`, `id=1'`, or `SELECT`); the terminal will infer `T1190` (Exploit Public-Facing Application).

### Q2: Why does the Blue Team Alerts feed show nothing after running an attack?
* **Explanation:** Blue Team only shows **Detections**. If your attack bypassed the existing Sigma rules, **no alert was fired** — this represents a **Detection Gap**.
* **Fix:** Check the **MITRE Matrix** to view the red Detection Gap. Deploy a Sigma rule matching the attack in the Blue Team editor and click **"Evaluate Active Rules"**.

### Q3: Why does the MITRE Matrix show techniques as "Untested"?
* **Explanation:** You might be scoped to a session that hasn't executed that attack yet.
* **Fix:** Use the **Scope Dropdown** at the top of the MITRE Matrix and select **"All Sessions (Aggregate)"** or ensure your active session ID matches the session where the command was executed.

### Q4: Can I run this without Docker or Kubernetes?
* **Yes!** The platform has built-in resilience. If Docker is not running, it automatically uses SQLite (`cyberrange.db`), local filesystem archiving for session recordings, and in-memory event buffering.

---

*Cyber Range & Security Validation Platform v2.0 — Engineered for Proving Cyber Resilience.*
