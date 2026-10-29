"""
Sigma Rule Compiler & Evaluator
Parses Sigma YAML rules, compiles them to OpenSearch queries, and evaluates real-time events.
"""
from typing import Any, Dict, List, Optional
import yaml
import re

from shared.schema import NormalizedEvent, Severity


class CompiledSigmaRule:
    def __init__(self, raw_yaml: str):
        self.raw_yaml = raw_yaml
        self.data: Dict[str, Any] = yaml.safe_load(raw_yaml)
        self.id = self.data.get("id", "unknown-rule")
        self.title = self.data.get("title", "Untitled Detection Rule")
        self.description = self.data.get("description", "")
        self.level = self.data.get("level", "medium").lower()

        # Extract MITRE technique from tags, e.g. attack.t1210 -> T1210
        self.mitre_technique = None
        self.mitre_tactic = None
        for tag in self.data.get("tags", []):
            if tag.lower().startswith("attack.ta"):
                self.mitre_tactic = tag.split(".")[-1].upper()
            elif tag.lower().startswith("attack.t"):
                self.mitre_technique = tag.split(".")[-1].upper()

        self.compiled_query = self._compile_opensearch_query()

    def _compile_opensearch_query(self) -> Dict[str, Any]:
        """Translates selection keywords into OpenSearch boolean query."""
        detection = self.data.get("detection", {})
        selection = detection.get("selection", {})
        terms = []

        for key, val in selection.items():
            if isinstance(val, list):
                for item in val:
                    terms.append({"match_phrase": {"action": item}})
            elif isinstance(val, str):
                terms.append({"match_phrase": {"action": val}})

        return {
            "query": {
                "bool": {
                    "should": terms,
                    "minimum_should_match": 1
                }
            }
        }

    def evaluate_event(self, event: NormalizedEvent) -> bool:
        """
        Evaluates whether an incoming NormalizedEvent triggers this Sigma rule.
        Does not evaluate detection events on themselves to avoid loops.
        """
        if event.source_type.value == "detection":
            return False

        detection = self.data.get("detection", {})
        selection = detection.get("selection", {})

        action_text = f"{event.action} {str(event.raw_payload)}".lower()

        for key, val in selection.items():
            # Check contains modifier
            if "|contains" in key:
                if isinstance(val, list):
                    for pattern in val:
                        if pattern.lower() in action_text:
                            return True
                elif isinstance(val, str) and val.lower() in action_text:
                    return True
            else:
                if isinstance(val, list):
                    for pattern in val:
                        if pattern.lower() in action_text:
                            return True
                elif isinstance(val, str) and val.lower() in action_text:
                    return True

        return False


class SigmaEngine:
    @staticmethod
    def load_rule_from_yaml(yaml_content: str) -> CompiledSigmaRule:
        return CompiledSigmaRule(yaml_content)

    @staticmethod
    def validate_sigma_syntax(yaml_content: str) -> Dict[str, Any]:
        """Validates that YAML follows minimal required Sigma specification."""
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                return {"valid": False, "error": "Rule content must be a YAML mapping"}
            required = ["title", "detection", "level"]
            missing = [r for r in required if r not in data]
            if missing:
                return {"valid": False, "error": f"Missing required Sigma fields: {missing}"}
            if "condition" not in data.get("detection", {}):
                return {"valid": False, "error": "Detection block requires 'condition'"}
            
            rule = CompiledSigmaRule(yaml_content)
            return {
                "valid": True,
                "rule_id": rule.id,
                "title": rule.title,
                "technique": rule.mitre_technique,
                "compiled_query": rule.compiled_query
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}
