# Comparison: This Platform vs. Traditional SIEMs (e.g., Microsoft Sentinel)

Standalone write-up of how the platform differs from an enterprise SIEM, and where it does **not**. Intended for the project report, viva, and demo narrative. It draws on `goal.md` and `architecture.md`.

> **Before you submit:** The statements about Microsoft Sentinel and other products reflect general, publicly known capabilities and change often. Verify each product claim against the vendor's current documentation and cite it in the final report. Claims about *our* platform are labelled by whether they are **designed** (in the docs) or **demonstrated** (shown working in the demo). Only demonstrated claims should be presented as fact.

---

## 1. TL;DR

A SIEM answers: **"What is happening in my environment, and did my detections fire?"**

This platform answers: **"If someone attacked this build right now, which techniques would we catch, how fast, and can I prove it and replay it?"**

The differentiator is **not** any single feature. Plenty of tools do attack simulation, plenty do detection, and Sentinel does detection and response very well. The differentiator is that **attack, detection, replay, validation and scoring all read and write one normalized event schema**, so questions that normally need manual stitching across tools become queries.

---

## 2. What Microsoft Sentinel Is (Briefly)

Microsoft Sentinel is a cloud-native SIEM/SOAR on Azure. In broad strokes it provides:

- **Log collection** from many sources through data connectors into a Log Analytics workspace.
- **Detection** through analytics rules (scheduled queries in KQL, near-real-time rules, built-in ML/fusion detections) producing alerts and incidents.
- **Investigation and hunting**: incident views, entity mapping, hunting queries, workbooks, notebooks.
- **Automation (SOAR)**: playbooks built on Azure Logic Apps; automation rules.
- **MITRE ATT&CK mapping**: analytics rules can be tagged with tactics/techniques, and a coverage view shows which techniques your **rules are mapped to**.
- **AI assistance** through Microsoft's own Security Copilot, which integrates with the Microsoft security stack.
- Deep integration with the Microsoft ecosystem (Entra ID, Defender products, Microsoft 365, Azure).

*(Verify current packaging: Microsoft has been consolidating Sentinel into its unified Defender portal. Check what the current state is before describing the product in the report.)*

It is a mature, production-grade product with scale, connectors, and a content ecosystem that a student project cannot and should not claim to match.

---

## 3. The Core Distinction

### 3.1 Passive vs. active

A SIEM is **detection-side**: it ingests what your environment produces and tells you what looks malicious. It does not generate attacks, so it can't tell you about techniques nobody has tried against you yet.

Our platform adds the **offensive side inside the same system**: attacks are run (manually or from scripted scenarios), and the same engine records whether each one was detected.

> **Wording caution:** `goal.md` calls traditional SIEMs "passive." Sentinel does have automated response (SOAR playbooks), so "passive" is only fair when meaning *"does not generate or validate attacks."* Prefer: **"detection-and-response only; no native attack emulation or detection-validation loop."**

### 3.2 Declared coverage vs. proven coverage

This is the sharpest point, and easiest to defend.

| | **SIEM MITRE coverage view** | **This platform** |
|---|---|---|
| What it shows | Which techniques your **rules are tagged** with | Which techniques were **actually attacked and actually detected** |
| Evidence | The existence of a rule | An attack event **and** a matching detection event in the same session within a time window |
| Failure mode | A rule exists, is tagged T1059, but doesn't fire in practice (bad log source, broken parsing, wrong field) and still shows as "covered" | Shows as **gap**; exposes the rule that exists but doesn't work |
| Output states | Typically covered / not covered by rules | **covered / gap / untested**: the "untested" state is the honest one |

Rule-tag coverage measures **intent**. Our validation measures **outcome**.

### 3.3 One schema, so validation is a query

In a typical enterprise, attack tooling output, sensor alerts, SIEM incidents, and the ATT&CK spreadsheet each have their own format, and the join is done by a person. Here, every event carries `session_id`, `mitre_technique`, `source_type`, `timestamp`, and `outcome` (`schema.md`), so "was T1210 detected in session X within 30 seconds of the attack?" is a join, not a project.

### 3.4 Replay as a regression test for detections

Existing practice: write a detection rule, hope it works, find out during a real incident. Here: every session is archived (terminal `.cast`, `.pcap`, event timeline), so a **new rule can be tested against a past attack** by re-emitting it on a flagged (`replay: true`) timeline. Detections get something analogous to a unit-test suite. Sentinel has historical data and retroactive hunting, but replaying a captured *attack* through a candidate rule as a repeatable test is not a native, packaged workflow in a typical SIEM deployment.

### 3.5 Traceability between pre-release and production

Because the same normalized schema and the same Detection Engine are used in both modes (`architecture.md`, two deployment topologies), a production incident can be linked through `build_id` back to the pre-release session where that build was attacked, and the team can see whether this technique was tested and caught beforehand.

---

## 4. Feature-by-Feature Comparison

Ratings are qualitative and reflect **what is designed**; do not present "this platform" cells as demonstrated unless you demo them.

| Capability | Microsoft Sentinel (typical) | This platform | Honest take |
|---|---|---|---|
| Scale and data connectors | Very large; hundreds of connectors | Small set (Falco, Suricata, a few sources) | **Sentinel wins decisively** |
| Production SIEM maturity | Enterprise-grade, SLAs, compliance | Prototype | **Sentinel wins decisively** |
| Query language / hunting | KQL, rich ecosystem | OpenSearch queries, Sigma | Comparable for the scope; Sentinel richer |
| Detection rule portability | KQL-centric | **Sigma** (vendor-neutral) compiled via pySigma | Platform's choice is a real portability advantage |
| Automated response (SOAR) | Strong (Logic Apps playbooks) | Not in scope | Sentinel wins |
| Attack emulation built in | Not a core SIEM function (adjacent Microsoft offerings exist; verify) | **Yes**: scripted scenarios + manual red-team terminal | **Platform's focus** |
| Detection validation | Rule-level MITRE mapping | **Outcome-based coverage** from attack/detect pairs | **Platform's focus** |
| Session recording and replay | No packaged equivalent | **Yes**: `.cast`, `.pcap`, event timeline | **Platform's focus** |
| Pre-release / CI gate | Not its role | **Yes**: build gets a pass/fail security report | **Platform's focus** |
| Readiness score | No single equivalent metric | Weighted Security Readiness Score | Platform's focus (see caveat 6.4) |
| AI assistant | Security Copilot (deep Microsoft integration) | Role-aware copilot grounded in session data | Different: ours is scoped to attack/detect/replay data; Microsoft's is broader across their stack |
| Cost | Usage-based licensing (ingestion volume) | Open-source stack; LLM API usage only | Platform cheaper to run at demo scale; not comparable at enterprise scale |
| Multi-tenancy | Mature | Logical isolation in design (see `security-considerations.md`) | Sentinel wins on maturity |

---

## 5. Where This Platform Fits in the Wider Landscape

Comparing only to Sentinel invites the objection *"but attack simulation tools exist."* Address it up front.

| Category | Examples | What they do | Gap this platform targets |
|---|---|---|---|
| **SIEM** | Microsoft Sentinel, Splunk, Elastic Security | Collect, detect, investigate | No attack emulation, no outcome-based coverage |
| **Breach & Attack Simulation (BAS)** | AttackIQ, SafeBreach, Picus | Run attack techniques against *your* environment and test controls | Typically sold separate from the SIEM; results integrated via connectors, not a shared native data model. Mostly validate controls in a live environment, not an isolated per-build sandbox |
| **Adversary emulation frameworks** | MITRE Caldera, Atomic Red Team | Open-source attack scenario execution | Execution only; no detection engine, replay, or scoring built in |
| **Cyber ranges** | Commercial and academic ranges | Training/exercise environments | Often training-oriented; not tied to CI/CD builds or continuous coverage computation |
| **Purple-team platforms** | Various | Coordinate red/blue exercises | Often workflow tools layered on others' data |

*(Verify product positioning from vendor sites before citing; this table is a framing aid, not a market survey.)*

**Honest framing:** none of the individual capabilities here is new. The contribution is **integrating them on one schema and loop**, applied to **per-build sandboxes** as a security gate, and then reusing the same detection engine for production monitoring. That is a defensible, specific claim. "We built a better SIEM" is not.

---

## 6. Limitations and Claims to Be Careful With

A reviewer will probe these. Having answers ready makes the project stronger.

### 6.1 "Zero shared data" is overstated
`goal.md` says pre-release testing and production monitoring have *zero shared data* in current practice. In reality many organizations do share some data (shared detection repos, DevSecOps pipelines, BAS tools feeding SIEMs). Safer wording: **"typically no common data model and no automated traceability between them."**

### 6.2 Sandbox coverage ≠ production coverage
The strongest-sounding claim, *"because the build was tested pre-release we know what production can detect"*, holds only if:
- the **same detection rules** run in both places,
- production produces **equivalent log sources** (a Falco sensor in the sandbox but no runtime sensor on production hosts means the detection can't fire there),
- the attack scenarios are **representative** of real adversary behavior.

State this explicitly: pre-release results are an **upper bound on what is detectable with these sensors and rules**, not a guarantee about production.

### 6.3 Detection coverage is only as good as the scenarios
"Covered" means *covered for the scenarios we ran.* One scripted test per technique is not proof against all variants of that technique. Untested is not the same as safe, which is why **untested** is a first-class state.

### 6.4 The readiness score is a heuristic
A weighted score (coverage %, latency, unresolved incidents) is a useful trend metric, but the weights are a design choice, not an industry standard. Document the formula and weights, show the sensitivity of the score to them, and don't present the number as an objective measure of "security." For the CI gate, prefer clear rules (e.g., *"fail if a previously detected technique is now undetected"*) alongside the score.

### 6.5 Prototype scale
Single-node Kafka/OpenSearch, a handful of scenarios, small sensor set. Compare **concept and architecture**, not throughput or connector breadth.

### 6.6 The platform adds attack surface
It hosts offensive tooling and untrusted code. A SIEM doesn't carry that risk to the same degree. This is the cost side of the differentiation. See `security-considerations.md`.

---

## 7. How to Prove It in the Demo

Claims land better as observed behavior. A suggested sequence, each step mapped to a differentiator:

| Step | What you show | Differentiator proven |
|---|---|---|
| 1 | Submit a build; sandbox appears automatically | Per-build isolated environment |
| 2 | Run a scripted attack scenario (e.g., 3-5 techniques) | Built-in attack emulation |
| 3 | Live blue dashboard shows alerts for some techniques but **not all** | Real detection with real misses |
| 4 | Coverage heatmap: some **covered**, some **gap** | Outcome-based coverage, not rule tagging |
| 5 | **Show a rule that exists and is tagged to a technique but fails to fire** → shown as *gap* | The key contrast with rule-tag coverage |
| 6 | Write or AI-draft a Sigma rule for the gap | Detection engineering loop |
| 7 | **Replay the same recorded session** with the new rule active → technique now **covered** | Replay as regression test |
| 8 | Readiness score before vs. after | Single trackable metric |
| 9 | (Stretch) Production event → trace via `build_id` to the pre-release session | Pre-release/production traceability |

Steps 5 and 7 are the most persuasive: they show something a rule-tag view cannot, and something a normal SIEM workflow doesn't give you.

---

## 8. Suggested Positioning Statements

Use whichever fits the audience; all are defensible against the caveats above.

- **One line:** *A security validation platform that proves which attacks your detections catch, replays attacks to test new rules, and uses the same engine as a pre-release gate and a production monitor.*
- **For a reviewer:** *Existing tools cover attack simulation, detection, and monitoring separately. We integrate them on one event schema so detection coverage is measured from real attack outcomes and every session is replayable.*
- **Versus Sentinel, specifically:** *Sentinel tells you what your rules are mapped to. We tell you what they actually caught, and let you test the next rule against yesterday's attack.*

### Avoid
- "Better than Sentinel" or "replaces Sentinel" (different scope and maturity).
- "Traditional SIEMs have no MITRE mapping" (false; they map rules, not outcomes).
- "Guarantees production security" (see 6.2).
- Any performance or scale comparison.

---

## 9. Open Questions to Resolve Before Finalizing

1. Verify each Sentinel capability statement and the current portal/packaging against Microsoft's documentation, and add citations.
2. Decide which of the Section 7 demo steps are realistically achievable in the timeline; remove claims from the report for steps that won't be demoed.
3. Decide the readiness-score formula and weights and document them (feeds `schema.md` `readiness_scores`).
4. Decide whether to include a short comparison against one BAS tool or Caldera, since reviewers may ask "why not just use X?"
