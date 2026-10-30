"""
MITRE ATT&CK Navigator Layer Generator & Coverage Correlator
Translates attack and detection event pairs into outcome-based coverage states.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.mitre_data import MITRE_TACTICS, MITRE_TECHNIQUES, TECHNIQUES_BY_ID
from shared.schema import NormalizedEvent, SourceType


class ValidationEngine:
    @staticmethod
    def calculate_coverage(
        events: List[NormalizedEvent],
        time_window_sec: float = 120.0
    ) -> Dict[str, Any]:
        """
        Correlates attacks with detections within time_window_sec.
        States:
        - covered: Attack event + Detection event for technique within window
        - gap: Attack event exists with NO matching detection event
        - untested: No attack event for technique in this session
        """
        attack_events: Dict[str, List[NormalizedEvent]] = {}
        detection_events: Dict[str, List[NormalizedEvent]] = {}

        for ev in events:
            tech = ev.mitre_technique
            if not tech:
                continue
            if ev.source_type == SourceType.ATTACK:
                attack_events.setdefault(tech, []).append(ev)
            elif ev.source_type == SourceType.DETECTION:
                detection_events.setdefault(tech, []).append(ev)

        technique_results: List[Dict[str, Any]] = []
        covered_count = 0
        gap_count = 0
        untested_count = 0
        simulated_count = 0

        for t in MITRE_TECHNIQUES:
            tid = t["technique_id"]
            t_attacks = attack_events.get(tid, [])
            t_detections = detection_events.get(tid, [])

            status = "untested"
            latency_sec: Optional[float] = None
            evidence = []

            # Simulation records can exercise UI/rule wiring, but must not count as observed coverage.
            # Check the canonical `provenance` field first (set by attack runner / terminal executor),
            # then fall back to the legacy raw_payload flags for backwards compatibility.
            live_attacks = [
                atk for atk in t_attacks
                if getattr(atk, "provenance", None) == "live"
                or atk.raw_payload.get("execution_mode") == "live"
                or (
                    "execution_mode" not in atk.raw_payload
                    and atk.raw_payload.get("executed_live") is True
                )
            ]
            simulated_attacks = [atk for atk in t_attacks if atk not in live_attacks]

            if live_attacks:
                # Match by explicit event linkage. Technique/time coincidence alone is insufficient.
                matched_attacks = []
                for atk in live_attacks:
                    for det in t_detections:
                        if det.raw_payload.get("triggering_event_id") != atk.event_id:
                            continue
                        delta = (det.timestamp - atk.timestamp).total_seconds()
                        if 0 <= delta <= time_window_sec:
                            matched_attacks.append((atk, det, delta))
                            evidence.append({
                                "attack_id": atk.event_id,
                                "detection_id": det.event_id,
                                "latency_sec": round(delta, 2),
                                "rule": det.action,
                                "correlation_method": "triggering_event_id",
                            })
                if matched_attacks:
                    status = "covered"
                    covered_count += 1
                    latency_sec = round(sum(m[2] for m in matched_attacks) / len(matched_attacks), 2)
                else:
                    status = "gap"
                    gap_count += 1
            elif simulated_attacks:
                status = "simulated"
                simulated_count += 1
            else:
                untested_count += 1

            seen_det_trigs = set()
            unique_detections = []
            for d in t_detections:
                trig = d.raw_payload.get("triggering_event_id") if d.raw_payload else None
                if trig:
                    if trig in seen_det_trigs:
                        continue
                    seen_det_trigs.add(trig)
                unique_detections.append(d)

            technique_results.append({
                "technique_id": tid,
                "tactic_id": t["tactic_id"],
                "tactic_name": MITRE_TACTICS.get(t["tactic_id"], {}).get("name", "Unknown"),
                "name": t["name"],
                "description": t["description"],
                "status": status,
                "attacks_count": len(t_attacks),
                "live_attacks_count": len(live_attacks),
                "simulated_attacks_count": len(simulated_attacks),
                "detections_count": len(unique_detections),
                "latency_sec": latency_sec,
                "evidence": evidence
            })

        tested_total = covered_count + gap_count
        coverage_pct = round((covered_count / tested_total * 100), 1) if tested_total > 0 else 0.0

        return {
            "tested_techniques": tested_total,
            "covered_count": covered_count,
            "gap_count": gap_count,
            "untested_count": untested_count,
            "simulated_count": simulated_count,
            "coverage_percentage": coverage_pct,
            "coverage_interpretation": "Only live attack events with explicit triggering-event linkage count as covered; simulated events are reported separately.",
            "techniques": technique_results
        }

    @staticmethod
    def generate_navigator_layer(coverage_data: Dict[str, Any], layer_name: str = "Cyber Range Security Validation") -> Dict[str, Any]:
        """
        Exports official MITRE ATT&CK Navigator Layer v4.5 JSON format.
        """
        techniques_list = []
        for item in coverage_data.get("techniques", []):
            color = "#64748b"  # Untested slate
            score = 0
            if item["status"] == "covered":
                color = "#10b981"  # Emerald green — live attack + linked detection
                score = 100
            elif item["status"] == "gap":
                color = "#ef4444"  # Crimson red — live attack, no detection
                score = 10
            elif item["status"] == "simulated":
                color = "#f59e0b"  # Amber — simulated-only, not observed on target
                score = 0

            techniques_list.append({
                "techniqueID": item["technique_id"],
                "tactic": MITRE_TACTICS.get(item["tactic_id"], {}).get("short", "discovery"),
                "score": score,
                "color": color,
                "comment": f"Status: {item['status'].upper()} | Attacks: {item['attacks_count']} | Detections: {item['detections_count']}",
                "enabled": True
            })

        return {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.5",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"Auto-generated outcome-based coverage layer. Overall Coverage: {coverage_data.get('coverage_percentage', 0)}%",
            "gradient": {
                "colors": ["#ef4444", "#f59e0b", "#10b981"],
                "minValue": 0,
                "maxValue": 100
            },
            "techniques": techniques_list
        }
