# Data Schema

This is the single most important technical artifact in the project — every service (attack engine, detection engine, replay engine, validation engine, copilot) reads and writes against this shared shape. Design changes here ripple everywhere, so treat this file as the source of truth and update it deliberately.

---

## 1. Normalized Event Schema (Kafka `normalized.events` / OpenSearch)

Every piece of security data in the platform — an attack action, a sensor alert, an analyst's note — is transformed into this one shape before it's stored.

```json
{
  "event_id": "uuid",
  "tenant_id": "00000000-0000-0000-0000-000000000123",
  "session_id": "sess-9f2a",
  "scenario_id": "uuid|null",
  "build_id": "uuid|null",
  "timestamp": "2026-10-22T10:15:03.120Z",
  "source_type": "attack | detection | network | host | soc_action",
  "source_name": "metasploit | falco | suricata | sigma_rule | analyst",
  "actor": "redteam_user_1 | system | analyst_name",
  "action": "nmap -sV target-pod:443",
  "mitre_tactic": "TA0007",
  "mitre_technique": "T1046",
  "severity": "low | medium | high | critical",
  "outcome": "succeeded | blocked | detected | undetected | null",
  "replay": false,
  "raw_payload": { }
}
```

### Field Notes
| Field | Required | Notes |
|---|---|---|
| `event_id` | Yes | Unique per event, generated at ingestion |
| `tenant_id` | Yes | Enforces multi-tenancy; every query is filtered by this first |
| `session_id` | Yes (except pure production events) | Links the event to a sandbox session; production-mode events may have `session_id: null` and rely on `build_id` instead |
| `scenario_id` | No | Set only when the event came from a scripted attack scenario (links back to the YAML definition) |
| `build_id` | No | Set when this event is associated with a specific CI/CD build — this is what enables tracing a production incident back to pre-release test history |
| `mitre_tactic` / `mitre_technique` | No, but required for anything feeding the Validation Engine | Follows MITRE ATT&CK's official IDs |
| `outcome` | No | Set by the Detection Engine when it determines whether an attack event was caught |
| `replay` | Yes, defaults `false` | `true` when this event was re-emitted by the Replay Engine, not generated live — lets dashboards visually distinguish live vs. replayed data |
| `raw_payload` | Yes | The original, untouched log/output from the source tool — never discard this, even after normalizing the top-level fields |

### Example: Attack Event
```json
{
  "event_id": "a1b2c3d4-0001",
  "tenant_id": "00000000-0000-0000-0000-000000000123",
  "session_id": "sess-9f2a",
  "scenario_id": "scn-brute-force-01",
  "build_id": null,
  "timestamp": "2026-10-22T10:15:03.120Z",
  "source_type": "attack",
  "source_name": "metasploit",
  "actor": "redteam_user_1",
  "action": "exploit/windows/smb/ms17_010_eternalblue",
  "mitre_tactic": "TA0001",
  "mitre_technique": "T1210",
  "severity": "high",
  "outcome": "succeeded",
  "replay": false,
  "raw_payload": { "module": "ms17_010_eternalblue", "target": "10.0.0.5", "result": "session opened" }
}
```

### Example: Detection Event
```json
{
  "event_id": "a1b2c3d4-0002",
  "tenant_id": "00000000-0000-0000-0000-000000000123",
  "session_id": "sess-9f2a",
  "scenario_id": null,
  "build_id": null,
  "timestamp": "2026-10-22T10:15:04.800Z",
  "source_type": "detection",
  "source_name": "sigma_rule",
  "actor": "system",
  "action": "rule:smb-exploit-attempt matched",
  "mitre_tactic": "TA0001",
  "mitre_technique": "T1210",
  "severity": "high",
  "outcome": "detected",
  "replay": false,
  "raw_payload": { "rule_id": "rule-0042", "matched_log": { "...falco output..." } }
}
```

---

## 2. PostgreSQL Tables (relational metadata)

### `tenants`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | |
| name | text | |
| created_at | timestamp | |

### `users`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | Mirrors Keycloak user id |
| tenant_id | uuid (FK) | |
| role | enum(red, blue, soc, admin) | |

### `labs`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | aka `lab_id` |
| tenant_id | uuid (FK) | Enforces multi-tenancy |
| name | text | Display name, e.g. "Vulnerable E-Commerce App v3" |
| description | text, nullable | |
| dockerfile_content | text, nullable | Raw Dockerfile, if uploaded directly |
| compose_content | text, nullable | Raw `docker-compose.yml`, if multi-container lab |
| image_tag | text, nullable | Set once built/identified |
| uploaded_by | uuid (FK → users) | User who created the lab |
| status | enum(uploaded, scanning, built, failed, archived) | Lifecycle state |
| safety_scan_result | jsonb | Trivy / Hadolint security findings |
| created_at | timestamp | |

### `sessions`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | aka `session_id` used in events |
| tenant_id | uuid (FK) | |
| lab_id | uuid (FK → labs), nullable | Lab environment this session was spawned from |
| build_id | uuid, nullable | Set in pre-release/CI mode |
| target_image | text | The uploaded Docker image reference |
| status | enum(creating, active, destroyed) | |
| created_at | timestamp | |
| destroyed_at | timestamp, nullable | |
| archive_path | text, nullable | MinIO path once archived |

### `scenarios`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | aka `scenario_id` |
| name | text | |
| description | text | |
| definition_yaml | text | The full scenario script |
| mitre_techniques | text[] | Techniques this scenario is expected to exercise |

### `sigma_rules`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | |
| tenant_id | uuid (FK) | |
| name | text | |
| mitre_technique | text | |
| sigma_yaml | text | Raw Sigma rule |
| compiled_query | text | Cached pySigma-compiled OpenSearch query |
| created_by | uuid (FK → users) | Supports "AI-generated vs. analyst-written" distinction |
| created_at | timestamp | |

### `builds`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | aka `build_id` |
| tenant_id | uuid (FK) | |
| commit_hash | text | From CI/CD webhook payload |
| image_tag | text | |
| readiness_score | numeric, nullable | Filled in after Phase 9 gate runs |
| gate_result | enum(pass, fail, pending) | |
| created_at | timestamp | |

### `readiness_scores`
| Column | Type | Notes |
|---|---|---|
| id | uuid (PK) | |
| session_id | uuid (FK), nullable | |
| build_id | uuid (FK), nullable | |
| coverage_pct | numeric | |
| avg_detection_latency_sec | numeric | |
| unresolved_incidents | integer | |
| score | numeric | Final weighted score |
| computed_at | timestamp | |

---

## 3. MITRE ATT&CK Reference Table (loaded once from STIX data)

### `mitre_techniques`
| Column | Type | Notes |
|---|---|---|
| technique_id | text (PK) | e.g. `T1210` |
| tactic_id | text | e.g. `TA0001` |
| name | text | |
| description | text | |
| sub_technique_of | text, nullable | For sub-techniques like `T1059.001` |

This table is loaded once (a seed script pulling MITRE's published STIX JSON) and never modified manually — only refreshed when MITRE publishes a new ATT&CK version.

---

## 4. Object Storage Layout (MinIO)

```
/sessions/{session_id}/terminal.cast
/sessions/{session_id}/network.pcap
/sessions/{session_id}/events.jsonl        (full normalized event batch for this session)
/sessions/{session_id}/manifest.json       (session metadata: start/end time, target_image, outcome summary)
```

The `manifest.json` is what the Replay Engine reads first to know what else exists for that session before pulling the larger files.

---

## Schema Change Policy
Any change to the normalized event schema's required fields must be reflected in:
1. This file
2. The ingestion/normalizer service's transform logic
3. Any OpenSearch index mapping
4. The Validation Engine's join logic (if `mitre_technique`/`session_id` semantics change)

Treat this file as versioned documentation — note the date and reason for any breaking change at the bottom.

### Change Log
- `2026-10-22` — Initial schema defined.
