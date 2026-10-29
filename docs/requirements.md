# Requirements

This document lists every tool, framework, and dependency needed to build the Unified AI-Powered Cyber Range & Security Validation Platform, organized by function. For each: what it's for, why it was chosen, and licensing status.

---

## 1. Identity & Access Management

| Tool | Purpose | License |
|---|---|---|
| **Keycloak** | SSO, JWT-based auth, role management (Red Team / Blue Team / SOC / Admin), multi-tenant realms | Open source, free |

---

## 2. Orchestration & Sandbox Isolation

| Tool | Purpose | License |
|---|---|---|
| **Kubernetes** | Namespace-per-session sandbox isolation, deployment lifecycle | Open source, free |
| **k3s** or **minikube** | Lightweight Kubernetes distribution suitable for a single-machine academic project | Open source, free |
| **Docker / Docker Engine** | Building and running container images (both the platform's own services and user-uploaded target builds) | Free (Docker Engine/CLI); Docker Desktop free for personal/small use |
| **OpenTofu** | Infrastructure-as-code: scripted creation/teardown of sandbox namespaces, network policies | Open source, free (fully open fork of Terraform) |
| **Kaniko** | Rootless, isolated image building (building user-uploaded Dockerfiles safely, not on a trusted host) | Open source, free |

---

## 3. Event Backbone & Storage (the shared data plane)

| Tool | Purpose | License |
|---|---|---|
| **Apache Kafka** | Central event stream — every attack action, detection alert, and SOC action flows through here | Apache 2.0, free |
| **PostgreSQL** | Relational storage: scenario definitions, Sigma rules, tenant/session metadata | Open source, free |
| **OpenSearch** | Log/event storage, search, and dashboards (Apache-licensed fork of Elasticsearch) | Apache 2.0, free |
| **OpenSearch Dashboards** | Visualization layer on top of OpenSearch (alerts, coverage heatmaps) | Apache 2.0, free |
| **MinIO** (or AWS S3 if using cloud credits) | Object storage for archived session recordings (`.cast`, `.pcap`, event batches) | Open source (MinIO), free |

---

## 4. Image & Dockerfile Scanning (pre-deployment safety check)

| Tool | Purpose | License |
|---|---|---|
| **Trivy** | Scans uploaded Docker images/Dockerfiles for known CVEs before building | Open source, free |
| **Hadolint** | Lints Dockerfiles for bad/insecure patterns before build | Open source, free |

---

## 5. Red Team Toolset

| Tool | Purpose | License |
|---|---|---|
| **Nmap** | Network/service reconnaissance | Open source, free |
| **Metasploit Framework** | Exploitation (CVE-based attacks against sandboxed target) | Open source, free (Pro edition is paid — not required) |
| **sqlmap** | SQL injection testing | Open source, free |
| **Burp Suite Community Edition** | Manual web app testing | Free (Pro edition with automated scanner is paid — not required for project scope) |
| **ttyd** | Browser-based terminal exposing the red team toolbox to the dashboard | Open source, free |
| **Apache Guacamole** | Browser-based GUI access (if full GUI tools like Burp's UI are needed, not just CLI) | Apache 2.0, free |

---

## 6. Blue Team / Detection & Monitoring Toolset

| Tool | Purpose | License |
|---|---|---|
| **Falco** | Runtime/syscall-level container security monitoring (CNCF project) | Open source, free |
| **Suricata** | Network intrusion detection (signature-based) | Open source, free |
| **Zeek** | Network traffic analysis (alternative/complement to Suricata) | Open source, free |
| **Wazuh** | Host-based SIEM/monitoring, log collection agent | Open source, free |
| **Sigma** + **pySigma** | Detection rule format + compiler (Sigma rules → OpenSearch queries) | Open source, free |
| **Filebeat** or **Fluent Bit** | Forwards sensor logs into Kafka/OpenSearch | Open source, free |

---

## 7. Recording & Replay Toolset

| Tool | Purpose | License |
|---|---|---|
| **asciinema** | Records red team terminal sessions (keystrokes + output) as replayable `.cast` files | Open source, free |
| **tcpdump** | Captures raw network traffic during a session (`.pcap`) | Free, standard Linux tool |
| **tcpreplay** | Re-injects captured `.pcap` traffic later to test new detection rules | Open source, free |

---

## 8. MITRE ATT&CK Reference Data

| Resource | Purpose | License |
|---|---|---|
| **MITRE ATT&CK STIX data** (GitHub: `mitre-attack/attack-stix-data`) | Canonical technique/tactic reference used for coverage mapping | Free, publicly published by MITRE |
| **MITRE ATT&CK Navigator** (layer JSON format) | Reusable open-source format for rendering the coverage heatmap | Open source, free |

---

## 9. AI Security Copilot

| Tool | Purpose | License / Cost |
|---|---|---|
| **Claude API (Anthropic)** | LLM powering the copilot: alert explanation, rule generation, attack-path suggestions, incident summarization | Paid, usage-based (token cost) — not free infrastructure, budget a small amount for demo usage |
| **FastAPI** | Python microservice framework exposing the copilot as an internal API | Open source, free |
| *(Optional free alternative)* **Ollama + local open-source LLM** | Zero-cost substitute for Claude API if budget must be $0; lower quality output | Open source, free (needs decent local compute) |

---

## 10. Application Layer (Dashboards & Services)

| Tool | Purpose | License |
|---|---|---|
| **React** | Frontend framework for Red Team / Blue Team / SOC / Admin dashboards | Open source, free |
| **FastAPI** (Python) | Backend services: ingestion, attack engine, detection engine, replay engine, validation engine, scoring engine | Open source, free |
| **confluent-kafka-python** (or `kafka-python`) | Kafka client library for producers/consumers in Python services | Open source, free |
| **Node.js** (if any JS-side services) | Runtime for frontend tooling/build | Open source, free |

---

## 11. Development & Supporting Tools

| Tool | Purpose | License |
|---|---|---|
| **Git / GitHub** | Version control | Free (public repos; private repos free within limits) |
| **GitHub Actions** (or Jenkins/GitLab CI) | CI/CD pipeline — triggers the pre-release sandbox security gate | Free tier sufficient for academic project |
| **Postman** or **Insomnia** | API testing during development | Free |
| **VS Code** | IDE | Free |

---

## 12. Hardware / Hosting Requirements

- Minimum: a single machine with **16 GB+ RAM** and a modern multi-core CPU (Kafka + OpenSearch + Kubernetes together are memory-hungry) — 32 GB recommended for comfortable demo performance.
- Virtualization support enabled (for Kubernetes/Docker nested containers).
- Optional: cloud credits (Azure for Students, AWS Educate, GCP free tier) if local hardware is insufficient — lets the project also claim a cloud deployment without added cost.
- No GPU required unless running a local LLM (Ollama) instead of the Claude API.

---

## Summary: Cost Reality
Every tool in this list is free and open source **except**:
1. **Claude API** usage (small, usage-based cost — can be substituted with a free local LLM if needed).
2. **Burp Suite Pro** and **Metasploit Pro** (optional paid upgrades — not required; free/community editions are sufficient for this project's scope).

Everything else — identity, orchestration, data plane, red/blue toolsets, recording, and the MITRE reference data — can be self-hosted at zero licensing cost.
