"""
Pre-Deployment Safety Scanner
Integrates Hadolint Dockerfile static analysis and Trivy container vulnerability scanning
via real subprocess CLI invocations, with built-in heuristic fallback when binaries are not installed.
"""
from datetime import datetime, timezone
import json
import logging
import re
import subprocess
import yaml
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberrange.scanner")


class SafetyScanner:
    @staticmethod
    def lint_dockerfile(dockerfile_content: str) -> Dict[str, Any]:
        """
        Inspects Dockerfile against security best practices using real Hadolint,
        falling back to built-in rule analyzer if Hadolint binary is not found.
        """
        # Try real Hadolint binary first
        try:
            proc = subprocess.run(
                ["hadolint", "--format", "json", "-"],
                input=dockerfile_content.encode("utf-8"),
                capture_output=True,
                timeout=10
            )
            raw_out = proc.stdout.decode("utf-8").strip()
            if raw_out:
                data = json.loads(raw_out)
                findings = []
                for item in data:
                    level = item.get("level", "warning").lower()
                    sev = "MEDIUM"
                    if level == "error":
                        sev = "CRITICAL"
                    elif level == "warning":
                        sev = "HIGH"
                    elif level == "info":
                        sev = "LOW"
                    findings.append({
                        "line": item.get("line", 1),
                        "rule": item.get("code", "DL0000"),
                        "severity": sev,
                        "message": item.get("message", "")
                    })

                criticals = sum(1 for f in findings if f["severity"] == "CRITICAL")
                highs = sum(1 for f in findings if f["severity"] == "HIGH")

                return {
                    "target": "Dockerfile",
                    "engine": "hadolint",
                    "mode": "real_tool",
                    "verified": True,
                    "passed": criticals == 0 and highs <= 1,
                    "total_findings": len(findings),
                    "critical_count": criticals,
                    "high_count": highs,
                    "findings": findings
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.debug(f"Hadolint binary invocation note ({e}); using internal rule analyzer.")

        # Fallback heuristic analyzer
        findings = []
        lines = dockerfile_content.splitlines()
        has_user_directive = False
        base_image = "unknown"

        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            if clean_line.upper().startswith("FROM "):
                parts = clean_line.split()
                if len(parts) > 1:
                    base_image = parts[1]
                if ":latest" in base_image or ":" not in base_image:
                    findings.append({
                        "line": idx,
                        "rule": "DL3007",
                        "severity": "MEDIUM",
                        "message": f"Using 'latest' tag or unpinned version for base image '{base_image}'"
                    })

            if clean_line.upper().startswith("USER "):
                if clean_line.split()[1] != "root":
                    has_user_directive = True

            if "sudo " in clean_line.lower():
                findings.append({
                    "line": idx,
                    "rule": "DL3004",
                    "severity": "HIGH",
                    "message": "Do not use sudo as it leads to unpredictable privilege escalation"
                })

            if re.search(r"curl\s+.*\|\s*(ba)?sh", clean_line) or re.search(r"wget\s+.*\|\s*(ba)?sh", clean_line):
                findings.append({
                    "line": idx,
                    "rule": "SEC001",
                    "severity": "CRITICAL",
                    "message": "Piping curl/wget directly to shell is dangerous and untrusted"
                })

            if clean_line.upper().startswith("ENV ") or clean_line.upper().startswith("ARG "):
                if re.search(r"(password|secret|token|api_key|private_key)\s*=\s*[^\s]+", clean_line, re.IGNORECASE):
                    findings.append({
                        "line": idx,
                        "rule": "SEC002",
                        "severity": "CRITICAL",
                        "message": "Potential hardcoded secret or credential found in ENV/ARG directive"
                    })

            if "apt-get update" in clean_line and "rm -rf /var/lib/apt/lists/*" not in clean_line:
                findings.append({
                    "line": idx,
                    "rule": "DL3009",
                    "severity": "LOW",
                    "message": "Delete the apt-get lists after installing packages to reduce image size"
                })

        if not has_user_directive and lines:
            findings.append({
                "line": len(lines),
                "rule": "DL3002",
                "severity": "HIGH",
                "message": "Last user is root; specify a non-root USER before entrypoint"
            })

        criticals = sum(1 for f in findings if f["severity"] == "CRITICAL")
        highs = sum(1 for f in findings if f["severity"] == "HIGH")

        return {
            "target": "Dockerfile",
            "base_image": base_image,
            "engine": "built-in Dockerfile heuristic analyzer",
            "mode": "heuristic",
            "verified": False,
            "passed": criticals == 0 and highs <= 1,
            "total_findings": len(findings),
            "critical_count": criticals,
            "high_count": highs,
            "findings": findings
        }


    @staticmethod
    def lint_compose(compose_content: str) -> Dict[str, Any]:
        """Parse a Compose document and flag host-level escape patterns before use."""
        try:
            document = yaml.safe_load(compose_content)
        except yaml.YAMLError as exc:
            return {"target": "docker-compose.yml", "engine": "compose-policy-check", "mode": "real_parser", "verified": True, "passed": False, "findings": [{"severity": "CRITICAL", "rule": "COMPOSE_INVALID_YAML", "message": str(exc)[:500]}]}
        services = document.get("services") if isinstance(document, dict) else None
        if not isinstance(services, dict) or not services:
            return {"target": "docker-compose.yml", "engine": "compose-policy-check", "mode": "real_parser", "verified": True, "passed": False, "findings": [{"severity": "CRITICAL", "rule": "COMPOSE_NO_SERVICES", "message": "Compose file must contain a non-empty services mapping"}]}

        findings = []
        for service_name, service in services.items():
            if not isinstance(service, dict):
                findings.append({"service": service_name, "severity": "CRITICAL", "rule": "COMPOSE_INVALID_SERVICE", "message": "Service definition must be a mapping"})
                continue
            if service.get("privileged") is True:
                findings.append({"service": service_name, "severity": "CRITICAL", "rule": "COMPOSE_PRIVILEGED", "message": "privileged: true is not allowed for uploaded labs"})
            if service.get("network_mode") == "host":
                findings.append({"service": service_name, "severity": "CRITICAL", "rule": "COMPOSE_HOST_NETWORK", "message": "Host network mode is not allowed"})
            if service.get("pid") == "host" or service.get("ipc") == "host":
                findings.append({"service": service_name, "severity": "CRITICAL", "rule": "COMPOSE_HOST_NAMESPACE", "message": "Host PID/IPC namespaces are not allowed"})
            for volume in service.get("volumes") or []:
                source = volume if isinstance(volume, str) else (volume.get("source", "") if isinstance(volume, dict) else "")
                normalized = str(source).replace("\\", "/").lower()
                if normalized.startswith(("/", "//")) or re.match(r"^[a-z]:/", normalized) or normalized in {"/", "/proc", "/sys", "/etc", "/root", "/home"}:
                    findings.append({"service": service_name, "severity": "CRITICAL", "rule": "COMPOSE_HOST_MOUNT", "message": f"Host path mount is not allowed: {source}"})
        criticals = sum(1 for item in findings if item["severity"] == "CRITICAL")
        return {"target": "docker-compose.yml", "engine": "compose-policy-check", "mode": "real_parser", "verified": True, "passed": criticals == 0, "total_findings": len(findings), "critical_count": criticals, "findings": findings}

    @staticmethod
    def get_scanner_metadata() -> Dict[str, Any]:
        """Queries scanner version and health status."""
        try:
            proc = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=5, check=False)
            if proc.returncode == 0:
                first_line = proc.stdout.splitlines()[0] if proc.stdout else "Trivy"
                return {"installed": True, "version": first_line.strip(), "engine": "Trivy"}
        except Exception:
            pass
        return {"installed": False, "version": None, "engine": "Trivy (not installed)"}

    @staticmethod
    def scan_image(image_reference: str, allow_vulnerable_target: bool = True) -> Dict[str, Any]:
        """Scan an existing image with Trivy against its exact reference or digest. Never synthesize findings."""
        now_iso = datetime.now(timezone.utc).isoformat()
        if not image_reference or not isinstance(image_reference, str):
            return {
                "image": image_reference, "scanner": "Trivy", "mode": "invalid_input",
                "status": "scan_failed",
                "verified": False, "passed": False, "error": "A non-empty image reference is required",
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "vulnerabilities": [],
                "scanned_at": now_iso
            }
        try:
            proc = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image_reference],
                capture_output=True, text=True, timeout=120, check=False
            )
        except FileNotFoundError:
            return {
                "image": image_reference, "scanner": "Trivy", "mode": "unavailable",
                "status": "scan_inconclusive",
                "verified": False, "passed": False,
                "error": "Trivy is not installed; image vulnerability status is unknown and the safety gate must not treat this as a clean scan.",
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "vulnerabilities": [],
                "scanned_at": now_iso
            }
        except subprocess.TimeoutExpired:
            return {
                "image": image_reference, "scanner": "Trivy", "mode": "timeout",
                "status": "scan_inconclusive",
                "verified": False, "passed": False,
                "error": "Trivy image scan exceeded the 120-second timeout; results are inconclusive.",
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "vulnerabilities": [],
                "scanned_at": now_iso
            }

        if proc.returncode != 0:
            return {
                "image": image_reference, "scanner": "Trivy", "mode": "failed",
                "status": "scan_failed",
                "verified": False, "passed": False,
                "error": (proc.stderr or f"Trivy exited with code {proc.returncode}")[:1000],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "vulnerabilities": [],
                "scanned_at": now_iso
            }
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return {
                "image": image_reference, "scanner": "Trivy", "mode": "invalid_output",
                "status": "scan_failed",
                "verified": False, "passed": False, "error": "Trivy did not return valid JSON",
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "vulnerabilities": [],
                "scanned_at": now_iso
            }

        vulnerabilities = []
        for res in data.get("Results") or []:
            for item in res.get("Vulnerabilities") or []:
                severity = str(item.get("Severity") or "UNKNOWN").upper()
                vulnerabilities.append({
                    "cve_id": item.get("VulnerabilityID", "CVE-UNKNOWN"),
                    "package": item.get("PkgName", "unknown"),
                    "installed_version": item.get("InstalledVersion", ""),
                    "fixed_version": item.get("FixedVersion", "N/A"),
                    "severity": severity,
                    "title": (item.get("Title") or item.get("Description") or "")[:120],
                    "target_image": image_reference,
                    "evidence_source": "trivy_cli"
                })
        counts = {level.lower(): sum(1 for item in vulnerabilities if item["severity"] == level)
                  for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        
        # Policy: In a cyber range, intentionally vulnerable images are permitted if allow_vulnerable_target is True.
        # However, passed is strictly recorded based on policy.
        passed_policy = counts["critical"] == 0 or allow_vulnerable_target

        return {
            "image": image_reference, "scanner": "Trivy", "mode": "real_tool",
            "status": "scan_complete",
            "verified": True, "passed": passed_policy,
            "has_critical": counts["critical"] > 0,
            "summary": counts, "total_findings": len(vulnerabilities),
            "vulnerabilities": vulnerabilities[:500],
            "scanned_at": now_iso
        }

