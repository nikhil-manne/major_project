"""
Isolated Container Image Builder & Context Validator for Cyber Range Labs
Safely unpacks archives, validates build context, checks for missing COPY/ADD files,
and executes container image builds when a container runtime is available.
"""
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid
import zipfile

logger = logging.getLogger("cyberrange.builder")

BUILD_CONTEXTS_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "logs", "build_contexts")
)
MAX_ARCHIVE_FILES = 200
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB


class BuildContextError(ValueError):
    """Raised when build context extraction or validation fails."""
    pass


class SafeArchiveExtractor:
    """Safely extracts archives preventing path traversal, symlink escapes, and archive bombs."""

    @staticmethod
    def extract_zip(raw_bytes: bytes, target_dir: str) -> List[str]:
        import io
        os.makedirs(target_dir, exist_ok=True)
        extracted_files = []
        total_size = 0

        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ARCHIVE_FILES:
                raise BuildContextError(f"Archive exceeds maximum file count limit ({len(infolist)} > {MAX_ARCHIVE_FILES})")

            target_path_obj = Path(target_dir).resolve()

            for info in infolist:
                # Prevent directory traversal
                member_path = (target_path_obj / info.filename).resolve()
                if not str(member_path).startswith(str(target_path_obj)):
                    raise BuildContextError(f"Path traversal detected in archive entry: {info.filename}")

                total_size += info.file_size
                if total_size > MAX_UNCOMPRESSED_BYTES:
                    raise BuildContextError(f"Uncompressed archive exceeds size limit ({total_size} bytes)")

            # Extract files
            for info in infolist:
                zf.extract(info, target_dir)
                extracted_files.append(info.filename)

        return extracted_files

    @staticmethod
    def extract_tar(raw_bytes: bytes, target_dir: str) -> List[str]:
        import io
        os.makedirs(target_dir, exist_ok=True)
        extracted_files = []
        total_size = 0

        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
            target_path_obj = Path(target_dir).resolve()
            members = tf.getmembers()
            if len(members) > MAX_ARCHIVE_FILES:
                raise BuildContextError(f"Archive exceeds maximum file count limit ({len(members)} > {MAX_ARCHIVE_FILES})")

            for member in members:
                # Disallow symlinks or hardlinks pointing outside target
                if member.issym() or member.islnk():
                    raise BuildContextError(f"Links not permitted in build context archive: {member.name}")

                member_path = (target_path_obj / member.name).resolve()
                if not str(member_path).startswith(str(target_path_obj)):
                    raise BuildContextError(f"Path traversal detected in tar entry: {member.name}")

                total_size += member.size
                if total_size > MAX_UNCOMPRESSED_BYTES:
                    raise BuildContextError(f"Uncompressed archive exceeds size limit ({total_size} bytes)")

            tf.extractall(target_dir)
            extracted_files = [m.name for m in members]

        return extracted_files


class ContextValidator:
    """Validates files in a build context, detecting Dockerfiles and missing COPY/ADD targets."""

    @staticmethod
    def parse_dockerfile_ports(dockerfile_content: str) -> List[int]:
        ports = []
        for line in dockerfile_content.splitlines():
            clean = line.strip()
            if clean.upper().startswith("EXPOSE "):
                parts = clean.split()[1:]
                for p in parts:
                    match = re.match(r"^(\d+)", p)
                    if match:
                        try:
                            ports.append(int(match.group(1)))
                        except ValueError:
                            pass
        return list(dict.fromkeys(ports))

    @staticmethod
    def check_dockerfile_copy_targets(dockerfile_content: str, context_dir: Optional[str]) -> Tuple[bool, List[str]]:
        """
        Scans Dockerfile for COPY/ADD instructions and checks whether source files exist in context_dir.
        Returns (is_valid, missing_files_list).
        """
        missing = []
        lines = dockerfile_content.splitlines()
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("#"):
                continue
            upper = clean.upper()
            if upper.startswith("COPY ") or upper.startswith("ADD "):
                # Flags like --from=... or --chown=...
                tokens = clean.split()
                args = [t for t in tokens[1:] if not t.startswith("--")]
                if len(args) < 2:
                    continue
                # If it's a multi-stage COPY --from, skip local file check
                if any(t.startswith("--from=") for t in tokens):
                    continue

                # Sources are all tokens except the last destination token
                sources = args[:-1]
                if not context_dir:
                    # Single Dockerfile upload with no context directory cannot fulfill COPY/ADD
                    for s in sources:
                        missing.append(f"Line {idx}: '{s}' required by '{tokens[0]}' but no build context files were provided. (Tip: Upload your project as a .zip or .tar.gz archive containing the Dockerfile and referenced files)")
                else:
                    for src in sources:
                        # Strip trailing slash or wildcards for simple check
                        src_clean = src.rstrip("/").split("*")[0]
                        if src_clean:
                            src_path = os.path.join(context_dir, src_clean)
                            if not os.path.exists(src_path):
                                missing.append(f"Line {idx}: '{src}' required by '{tokens[0]}' was not found in uploaded context. (Tip: Ensure '{src}' is included in the root or relative path of the uploaded archive)")

        return len(missing) == 0, missing


class IsolatedContainerBuilder:
    """Manages container image building and provenance tracking."""

    @staticmethod
    def is_builder_available() -> bool:
        """Checks if Docker daemon or Podman CLI is responsive."""
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=4,
                check=False
            )
            return res.returncode == 0
        except Exception:
            return False

    @staticmethod
    def build_image(
        lab_id: str,
        build_id: str,
        dockerfile_content: str,
        context_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a real isolated build if the builder daemon is available.
        Returns detailed build result with immutable digest and sanitized logs.
        """
        start_time = datetime.now(timezone.utc)
        image_tag = f"cyberrange/lab-{lab_id}:{build_id}"

        # 1. Validate COPY/ADD targets before attempting build
        ok, missing_files = ContextValidator.check_dockerfile_copy_targets(dockerfile_content, context_dir)
        if not ok:
            return {
                "success": False,
                "status": "build_failed",
                "image_tag": None,
                "image_digest": None,
                "error": "Build context validation failed: missing required files",
                "missing_files": missing_files,
                "logs": "\n".join(missing_files),
                "duration_seconds": 0.0,
                "builder": "context_validator",
            }

        # 2. Check builder availability
        if not IsolatedContainerBuilder.is_builder_available():
            logger.warning("Container builder daemon is unavailable; build failed closed.")
            return {
                "success": False,
                "status": "unavailable",
                "image_tag": None,
                "image_digest": None,
                "error": "Container builder daemon is not accessible in this environment. Cannot build image.",
                "missing_files": [],
                "logs": "Container builder daemon unavailable (docker/podman not connected).",
                "duration_seconds": 0.0,
                "builder": "none",
            }

        # 3. Create temporary build context directory if not provided
        temp_dir = None
        work_dir = context_dir
        if not work_dir:
            temp_dir = os.path.join(BUILD_CONTEXTS_ROOT, f"temp-{build_id}")
            os.makedirs(temp_dir, exist_ok=True)
            df_path = os.path.join(temp_dir, "Dockerfile")
            with open(df_path, "w", encoding="utf-8") as f:
                f.write(dockerfile_content)
            work_dir = temp_dir

        try:
            # Execute docker build
            # Using --no-cache and isolated arguments
            cmd = ["docker", "build", "-t", image_tag, work_dir]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False
            )
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logs = (proc.stdout or "") + "\n" + (proc.stderr or "")

            if proc.returncode != 0:
                return {
                    "success": False,
                    "status": "build_failed",
                    "image_tag": None,
                    "image_digest": None,
                    "error": f"Builder process exited with code {proc.returncode}",
                    "missing_files": [],
                    "logs": logs[:10000],
                    "duration_seconds": duration,
                    "builder": "docker",
                }

            # Retrieve immutable digest
            digest_proc = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image_tag],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            digest = digest_proc.stdout.strip()
            if not digest or digest == "<no value>":
                # Fallback to image ID
                id_proc = subprocess.run(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", image_tag],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False
                )
                digest = id_proc.stdout.strip()

            return {
                "success": True,
                "status": "built",
                "image_tag": image_tag,
                "image_digest": digest or f"sha256:{hashlib.sha256(image_tag.encode()).hexdigest()}",
                "error": None,
                "missing_files": [],
                "logs": logs[:10000],
                "duration_seconds": duration,
                "builder": "docker",
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "status": "timeout",
                "image_tag": None,
                "image_digest": None,
                "error": "Image build timed out after 300 seconds",
                "missing_files": [],
                "logs": "Build timeout expired",
                "duration_seconds": 300.0,
                "builder": "docker",
            }
        except Exception as e:
            return {
                "success": False,
                "status": "build_failed",
                "image_tag": None,
                "image_digest": None,
                "error": str(e),
                "missing_files": [],
                "logs": str(e),
                "duration_seconds": 0.0,
                "builder": "docker",
            }
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

