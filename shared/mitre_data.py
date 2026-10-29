"""
MITRE ATT&CK Canonical Reference Catalogue
Pre-loaded STIX dataset representation for validation and coverage mapping.
"""

MITRE_TACTICS = {
    "TA0043": {"id": "TA0043", "name": "Reconnaissance", "short": "reconnaissance"},
    "TA0001": {"id": "TA0001", "name": "Initial Access", "short": "initial-access"},
    "TA0002": {"id": "TA0002", "name": "Execution", "short": "execution"},
    "TA0003": {"id": "TA0003", "name": "Persistence", "short": "persistence"},
    "TA0004": {"id": "TA0004", "name": "Privilege Escalation", "short": "privilege-escalation"},
    "TA0005": {"id": "TA0005", "name": "Defense Evasion", "short": "defense-evasion"},
    "TA0006": {"id": "TA0006", "name": "Credential Access", "short": "credential-access"},
    "TA0007": {"id": "TA0007", "name": "Discovery", "short": "discovery"},
    "TA0008": {"id": "TA0008", "name": "Lateral Movement", "short": "lateral-movement"},
    "TA0009": {"id": "TA0009", "name": "Collection", "short": "collection"},
    "TA0011": {"id": "TA0011", "name": "Command and Control", "short": "command-and-control"},
    "TA0010": {"id": "TA0010", "name": "Exfiltration", "short": "exfiltration"},
    "TA0040": {"id": "TA0040", "name": "Impact", "short": "impact"},
}

MITRE_TECHNIQUES = [
    {
        "technique_id": "T1046",
        "tactic_id": "TA0007",
        "name": "Network Service Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts (e.g. Nmap SYN scans, port probes)."
    },
    {
        "technique_id": "T1210",
        "tactic_id": "TA0008",
        "name": "Exploitation of Remote Services",
        "description": "Adversaries may exploit remote services to gain unauthorized access or move laterally (e.g. EternalBlue MS17-010, Log4Shell)."
    },
    {
        "technique_id": "T1059",
        "tactic_id": "TA0002",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters (e.g. bash, sh, python) to execute arbitrary commands."
    },
    {
        "technique_id": "T1190",
        "tactic_id": "TA0001",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may take advantage of a weakness in an Internet-facing computer or program (e.g. SQL Injection, RCE)."
    },
    {
        "technique_id": "T1078",
        "tactic_id": "TA0005",
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, or Privilege Escalation."
    },
    {
        "technique_id": "T1082",
        "tactic_id": "TA0007",
        "name": "System Information Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system and hardware, including version, patches, and architecture."
    },
    {
        "technique_id": "T1053",
        "tactic_id": "TA0003",
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse task scheduling functionality (e.g. cron, systemd timers) to facilitate initial or recurring code execution."
    },
    {
        "technique_id": "T1021",
        "tactic_id": "TA0008",
        "name": "Remote Services",
        "description": "Adversaries may use Valid Accounts to log into remote services such as SSH, VNC, RDP or SMB."
    },
    {
        "technique_id": "T1041",
        "tactic_id": "TA0010",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel."
    },
    {
        "technique_id": "T1499",
        "tactic_id": "TA0040",
        "name": "Endpoint Denial of Service",
        "description": "Adversaries may perform Endpoint Denial of Service attacks to degrade or block the availability of targeted systems."
    },
    {
        "technique_id": "T1595",
        "tactic_id": "TA0043",
        "name": "Active Scanning",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting."
    },
    {
        "technique_id": "T1003",
        "tactic_id": "TA0006",
        "name": "OS Credential Dumping",
        "description": "Adversaries may dump credentials from the operating system to obtain account login and credential material."
    }
]

TECHNIQUES_BY_ID = {t["technique_id"]: t for t in MITRE_TECHNIQUES}
