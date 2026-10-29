"""
Session Archiver & Storage Manager
Bundles terminal casts, real network PCAP captures, event streams, and manifests for MinIO/S3 object storage,
with local disk mirroring and PostgreSQL session tracking.
"""
from datetime import datetime, timezone
import json
import base64
import binascii
import re
import logging
import os
import struct
from typing import Any, Dict, List, Optional

from shared.schema import NormalizedEvent, SessionManifest
from shared.s3_client import s3_client
from shared.db import db_context, SessionModel
from services.ingestion.opensearch_sink import event_sink
from services.attack_engine.service import session_casts, session_cast_modes
from services.orchestrator.k8s_client import k8s_client

logger = logging.getLogger("cyberrange.archiver")

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)


def generate_valid_pcap_header() -> bytes:
    """Generates standard libpcap 2.4 global file header (24 bytes)."""
    magic_number = 0xa1b2c3d4  # Microsecond resolution pcap
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # LINKTYPE_ETHERNET
    return struct.pack("=IHHiIII", magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network)


def inspect_pcap(path: str) -> Dict[str, Any]:
    """Validate a classic PCAP file and count complete packet records."""
    try:
        with open(path, "rb") as stream_file:
            content = stream_file.read()
        if len(content) < 24:
            return {"valid": False, "packet_count": 0, "bytes": len(content), "reason": "file shorter than PCAP global header"}
        if content[:4] not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
            return {"valid": False, "packet_count": 0, "bytes": len(content), "reason": "unknown PCAP magic number"}
        endian = "<" if content[:4] in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
        offset = 24
        packet_count = 0
        while offset < len(content):
            if offset + 16 > len(content):
                return {"valid": False, "packet_count": packet_count, "bytes": len(content), "reason": "truncated packet header"}
            _sec, _usec, incl_len, orig_len = struct.unpack(endian + "IIII", content[offset:offset + 16])
            if incl_len > 16 * 1024 * 1024 or orig_len < incl_len or offset + 16 + incl_len > len(content):
                return {"valid": False, "packet_count": packet_count, "bytes": len(content), "reason": "invalid or truncated packet record"}
            packet_count += 1
            offset += 16 + incl_len
        return {"valid": True, "packet_count": packet_count, "bytes": len(content), "reason": None}
    except OSError as exc:
        return {"valid": False, "packet_count": 0, "bytes": 0, "reason": str(exc)}


class SessionArchiver:
    @staticmethod
    def archive_session(session_id: str, tenant_id: str) -> Dict[str, Any]:
        """
        Creates full archival package for session and uploads to MinIO S3 bucket:
        - /sessions/{session_id}/events.jsonl
        - /sessions/{session_id}/terminal.cast
        - /sessions/{session_id}/network.pcap
        - /sessions/{session_id}/manifest.json
        """
        if not re.fullmatch(r"sess-[A-Za-z0-9_-]{1,64}", session_id or ""):
            raise ValueError("Invalid session ID format")
        if not tenant_id or len(tenant_id) > 128:
            raise ValueError("Invalid tenant ID")
        session_folder = os.path.join(STORAGE_DIR, session_id)
        os.makedirs(session_folder, exist_ok=True)

        # 1. Fetch events
        events = event_sink.query_events(tenant_id=tenant_id, session_id=session_id, limit=1000)
        events_jsonl_content = "\n".join(ev.model_dump_json() for ev in events) + "\n"
        events_path = os.path.join(session_folder, "events.jsonl")
        with open(events_path, "w", encoding="utf-8") as f:
            f.write(events_jsonl_content)

        # Upload to MinIO
        s3_events_uploaded = s3_client.upload_text(events_jsonl_content, f"/sessions/{session_id}/events.jsonl")

        # 2. Terminal cast
        actual_cast = session_casts.get(session_id)
        cast_has_entries = bool(actual_cast and len(actual_cast) > 1)
        cast_mode = session_cast_modes.get(session_id, "unavailable")
        terminal_recorded = cast_has_entries and cast_mode == "live"
        cast_simulated = cast_has_entries and not terminal_recorded
        cast = actual_cast if cast_has_entries else [
            {"version": 2, "width": 120, "height": 36, "timestamp": int(datetime.now(timezone.utc).timestamp())},
            [0.0, "o", "No terminal recording was available for this session.\r\n"]
        ]
        cast_content = "\n".join(json.dumps(line) for line in cast) + "\n"
        cast_path = os.path.join(session_folder, "terminal.cast")
        with open(cast_path, "w", encoding="utf-8") as f:
            f.write(cast_content)

        s3_terminal_uploaded = s3_client.upload_text(cast_content, f"/sessions/{session_id}/terminal.cast")
        terminal_recording = {
            "status": "recorded" if terminal_recorded else ("simulated" if cast_simulated else "unavailable"),
            "source": "terminal_command_api" if terminal_recorded else ("simulated_attack_runner" if cast_simulated else "placeholder"),
            "execution_mode": cast_mode,
            "entries": max(0, len(cast) - 1) if (terminal_recorded or cast_simulated) else 0,
            "bytes": len(cast_content.encode("utf-8")),
            "note": None if terminal_recorded else ("Transcript entries were generated in simulation or mixed mode; they are not a verified live terminal recording." if cast_simulated else "The file is a placeholder; no terminal recording was available."),
        }

        # 3. Try retrieving the actual capture through the Kubernetes API.
        pcap_path = os.path.join(session_folder, "network.pcap")
        capture_status = "unavailable"
        capture_source = None
        capture_validation = {"valid": False, "packet_count": 0, "bytes": 0, "reason": "no capture source available"}
        encoded = k8s_client.export_pcap_base64(session_id)
        if encoded:
            try:
                pcap_bytes = base64.b64decode(encoded, validate=True)
                with open(pcap_path, "wb") as wf:
                    wf.write(pcap_bytes)
                capture_validation = inspect_pcap(pcap_path)
                if capture_validation["valid"] and capture_validation["packet_count"] > 0:
                    capture_status = "captured"
                    capture_source = "kubernetes_tcpdump_sidecar"
                else:
                    capture_status = "empty_or_invalid"
            except (binascii.Error, ValueError, OSError) as exc:
                capture_status = "invalid_capture"
                capture_validation["reason"] = str(exc)

        if capture_status != "captured":
            # A standards-compliant header-only placeholder is useful for consumers, but is
            # explicitly labelled unavailable and must never be represented as captured traffic.
            with open(pcap_path, "wb") as f:
                f.write(generate_valid_pcap_header())
            capture_validation = inspect_pcap(pcap_path)
            capture_validation["reason"] = capture_validation.get("reason") or "header-only placeholder; no packet records captured"
            capture_source = "placeholder_header_only"

        s3_network_uploaded = s3_client.upload_file(pcap_path, f"/sessions/{session_id}/network.pcap")

        # 4. Manifest
        attack_count = sum(1 for e in events if e.source_type.value == "attack")
        detection_count = sum(1 for e in events if e.source_type.value == "detection")
        techniques_exercised = list({e.mitre_technique for e in events if e.mitre_technique and e.source_type.value == "attack"})
        techniques_detected = list({e.mitre_technique for e in events if e.mitre_technique and e.source_type.value == "detection"})

        target_image = "unknown"
        build_id = None
        session_execution_mode = "simulated"
        with db_context() as db:
            s_row = db.query(SessionModel).filter_by(id=session_id).first()
            if s_row:
                target_image = s_row.target_image
                build_id = s_row.build_id
                session_execution_mode = (s_row.isolation or {}).get("execution_mode", "simulated")
                s_row.archive_path = f"/sessions/{session_id}"
                db.commit()

        manifest = {
            "session_id": session_id,
            "tenant_id": tenant_id,
            "build_id": build_id,
            "target_image": target_image,
            "status": "archived",
            "execution_mode": session_execution_mode,
            "archived_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "attack_events": attack_count,
            "detection_events": detection_count,
            "techniques_exercised": techniques_exercised,
            "techniques_detected": techniques_detected,
            "files": {
                "events": f"/sessions/{session_id}/events.jsonl",
                "terminal": f"/sessions/{session_id}/terminal.cast",
                "network": f"/sessions/{session_id}/network.pcap"
            },
            "terminal_recording": terminal_recording,
            "network_capture": {
                "status": capture_status,
                "source": capture_source,
                "packet_count": capture_validation.get("packet_count", 0),
                "bytes": capture_validation.get("bytes", 0),
                "validation": capture_validation,
                "uploaded_to_object_storage": bool(s3_network_uploaded),
            },
            "object_storage": {
                "configured": bool(s3_client.is_available),
                "events_uploaded": bool(s3_events_uploaded),
                "terminal_uploaded": bool(s3_terminal_uploaded),
            }
        }

        manifest_path = os.path.join(session_folder, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        s3_client.upload_json(manifest, f"/sessions/{session_id}/manifest.json")

        return manifest

    @staticmethod
    def list_archived_sessions() -> List[Dict[str, Any]]:
        manifests = []
        # Try local storage
        if os.path.exists(STORAGE_DIR):
            for sid in os.listdir(STORAGE_DIR):
                m_path = os.path.join(STORAGE_DIR, sid, "manifest.json")
                if os.path.exists(m_path):
                    try:
                        with open(m_path, "r", encoding="utf-8") as f:
                            manifests.append(json.load(f))
                    except Exception:
                        pass

        # Try MinIO if local was empty
        if not manifests and s3_client.is_available:
            keys = s3_client.list_keys("sessions/")
            manifest_keys = [k for k in keys if k.endswith("manifest.json")]
            for mk in manifest_keys:
                m = s3_client.get_json(mk)
                if m:
                    manifests.append(m)

        return sorted(manifests, key=lambda m: m.get("archived_at", ""), reverse=True)

    @staticmethod
    def get_manifest(session_id: str) -> Optional[Dict[str, Any]]:
        if not re.fullmatch(r"sess-[A-Za-z0-9_-]{1,64}", session_id or ""):
            return None
        # 1. Try MinIO
        m = s3_client.get_json(f"/sessions/{session_id}/manifest.json")
        if m:
            return m

        # 2. Fall back to local
        m_path = os.path.join(STORAGE_DIR, session_id, "manifest.json")
        if os.path.exists(m_path):
            with open(m_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None
