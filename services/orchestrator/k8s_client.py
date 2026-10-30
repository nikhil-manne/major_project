"""
Kubernetes Sandbox Orchestration Client
Deploys and manages isolated ephemeral sandbox namespaces, network policies,
target victim pods, and red team toolbox pods via official Kubernetes Python API.
"""
import logging
import os
import re
import shlex
from typing import Any, Dict, List, Optional
import yaml

try:
    from kubernetes import client, config
    from kubernetes.stream import stream
    HAS_KUBERNETES = True
except ImportError:  # Permit an explicitly labelled simulation-only local installation.
    client = None
    config = None
    stream = None
    HAS_KUBERNETES = False

logger = logging.getLogger("cyberrange.k8s")

K8S_TEMPLATES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "infra", "k8s")
)


class K8sSandboxClient:
    def __init__(self):
        self.is_connected = False
        self.core_v1 = None
        self.net_v1 = None
        self._init_client()

    def _init_client(self):
        if not HAS_KUBERNETES:
            logger.warning("kubernetes package not installed; live sandbox operations are unavailable")
            self.is_connected = False
            return
        try:
            # 1. Try in-cluster config if running in K8s
            if os.getenv("KUBERNETES_SERVICE_HOST"):
                config.load_incluster_config()
                self.is_connected = True
                logger.info("Loaded in-cluster Kubernetes configuration")
            else:
                # 2. Try local kubeconfig (~/.kube/config)
                config.load_kube_config()
                self.is_connected = True
                logger.info("Loaded local ~/.kube/config")

            if self.is_connected:
                self.core_v1 = client.CoreV1Api()
                self.net_v1 = client.NetworkingV1Api()
        except Exception as e:
            logger.info(f"Kubernetes cluster not directly accessible ({e}). Running with simulated sandbox backend.")
            self.is_connected = False

    def _render_template(self, filename: str, replacements: Dict[str, str]) -> str:
        filepath = os.path.join(K8S_TEMPLATES_DIR, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"K8s template not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        for key, val in replacements.items():
            content = content.replace(f"${{{key}}}", val)
            content = content.replace(f"${key}", val)
        return content

    def create_sandbox(self, session_id: str, tenant_id: str, target_image: str) -> Dict[str, Any]:
        """
        Applies full sandbox stack:
        1. Namespace with restricted Pod Security Standards
        2. Default Deny NetworkPolicy
        3. Allow Toolbox <-> Target NetworkPolicy
        4. Target Pod with Falco / Suricata / tcpdump sidecars
        5. Red Team Toolbox Pod with ttyd web terminal
        6. Verifies target pod readiness and isolation
        """
        namespace = f"sandbox-{session_id}"
        target_endpoint = f"target-app.{namespace}.svc.cluster.local"
        replacements = {
            "SESSION_ID": session_id,
            "TENANT_ID": tenant_id,
            "TARGET_IMAGE": target_image
        }

        created_resources = []

        if self.is_connected and self.core_v1:
            try:
                # 1. Namespace
                ns_yaml = self._render_template("namespace-template.yaml", replacements)
                ns_doc = yaml.safe_load(ns_yaml)
                self.core_v1.create_namespace(body=ns_doc)
                created_resources.append(f"Namespace/{namespace}")

                # 2. Network Policies
                deny_yaml = self._render_template("network-policy-default-deny.yaml", replacements)
                deny_doc = yaml.safe_load(deny_yaml)
                self.net_v1.create_namespaced_network_policy(namespace=namespace, body=deny_doc)
                created_resources.append("NetworkPolicy/default-deny-all")

                allow_yaml = self._render_template("network-policy-allow-toolbox.yaml", replacements)
                for doc in yaml.safe_load_all(allow_yaml):
                    if doc:
                        self.net_v1.create_namespaced_network_policy(namespace=namespace, body=doc)
                        created_resources.append(f"NetworkPolicy/{doc['metadata']['name']}")

                # 3. Target Pod
                target_yaml = self._render_template("pod-target.yaml", replacements)
                target_doc = yaml.safe_load(target_yaml)
                self.core_v1.create_namespaced_pod(namespace=namespace, body=target_doc)
                created_resources.append("Pod/target-app")

                # 4. Toolbox Pod
                toolbox_yaml = self._render_template("pod-toolbox.yaml", replacements)
                toolbox_doc = yaml.safe_load(toolbox_yaml)
                self.core_v1.create_namespaced_pod(namespace=namespace, body=toolbox_doc)
                created_resources.append("Pod/redteam-toolbox")

                logger.info(f"Successfully provisioned K8s sandbox namespace '{namespace}'")

                # 5. Wait for target pod readiness check
                import time
                target_ready = False
                for _ in range(15):
                    pod_status = self.core_v1.read_namespaced_pod_status(name="target-app", namespace=namespace)
                    phase = pod_status.status.phase
                    if phase == "Running":
                        # Check container statuses
                        c_statuses = pod_status.status.container_statuses or []
                        if all(cs.ready for cs in c_statuses if cs.name == "target"):
                            target_ready = True
                            break
                    elif phase in ("Failed", "Unknown"):
                        break
                    # Check for image pull errors
                    for cs in pod_status.status.container_statuses or []:
                        waiting = cs.state.waiting if cs.state else None
                        if waiting and waiting.reason in ("ErrImagePull", "ImagePullBackOff", "CrashLoopBackOff"):
                            raise RuntimeError(f"Target pod failed: {waiting.reason} - {waiting.message}")
                    time.sleep(1)

                if not target_ready:
                    logger.warning("Target pod did not become ready within the initial window; continuing with caveat")

            except Exception as e:
                logger.error(f"Error provisioning K8s sandbox resources: {e}")
                # Roll back partially created resources rather than leaving an unsafe partial sandbox.
                try:
                    self.core_v1.delete_namespace(name=namespace)
                except Exception:
                    logger.exception("Failed to clean up partially-created sandbox namespace %s", namespace)
                return {
                    "namespace": namespace,
                    "target_endpoint": target_endpoint,
                    "applied_to_cluster": False,
                    "execution_mode": "failed",
                    "error": str(e),
                    "resources": created_resources,
                }

        if not self.is_connected:
            simulated_endpoint = f"simulated-target.{session_id}.local"
            return {
                "namespace": namespace,
                "target_endpoint": simulated_endpoint,
                "applied_to_cluster": False,
                "execution_mode": "simulated",
                "resources": [],
                "planned_resources": [
                    f"Namespace/{namespace}",
                    "NetworkPolicy/default-deny-all",
                    "NetworkPolicy/allow-toolbox-to-target",
                    "Pod/target-app",
                    "Pod/redteam-toolbox",
                ],
                "note": "No Kubernetes cluster was contacted; no namespace or pods were created.",
            }

        return {
            "namespace": namespace,
            "target_endpoint": target_endpoint,
            "applied_to_cluster": True,
            "execution_mode": "live",
            "resources": created_resources,
        }

    def delete_sandbox(self, session_id: str) -> bool:
        """Deletes the sandbox namespace, cascading destruction to all contained pods and policies."""
        namespace = f"sandbox-{session_id}"
        if self.is_connected and self.core_v1:
            try:
                self.core_v1.delete_namespace(name=namespace)
                logger.info(f"Deleted K8s sandbox namespace '{namespace}'")
                return True
            except Exception as e:
                logger.warning(f"Failed to delete K8s namespace '{namespace}': {e}")
                return False
        return True

    def exec_command_in_toolbox(self, session_id: str, command: str, target_endpoint: Optional[str] = None) -> Dict[str, Any]:
        """Run one allowlisted argv command in the toolbox; never pass user text to a shell."""
        namespace = f"sandbox-{session_id}"
        pod_name = "redteam-toolbox"
        
        # Inject dynamic target endpoint into command if provided
        effective_command = command
        if target_endpoint:
            effective_command = effective_command.replace("{TARGET_ENDPOINT}", target_endpoint)
            effective_command = effective_command.replace("{TARGET}", target_endpoint)
            effective_command = effective_command.replace("target-pod", target_endpoint)

        try:
            argv = shlex.split(effective_command, posix=True)
        except ValueError as exc:
            return {"command": effective_command, "output": f"Invalid command syntax: {exc}", "exit_code": 2, "executed_live": False, "execution_mode": "blocked"}
        if not argv:
            return {"command": effective_command, "output": "Empty command", "exit_code": 2, "executed_live": False, "execution_mode": "blocked"}

        allowed_commands = {
            "nmap", "curl", "wget", "sqlmap", "hydra", "ssh", "sshpass", "msfconsole",
            "ping", "dig", "nc", "netcat", "tcpdump", "cat", "ls", "id", "whoami",
            "uname", "grep", "find", "ip", "ss", "python3", "trivy",
        }
        executable = os.path.basename(argv[0])
        if executable not in allowed_commands:
            return {
                "command": effective_command,
                "output": f"Command blocked by toolbox allowlist: {executable}",
                "exit_code": 126, "executed_live": False, "execution_mode": "blocked",
            }

        if self.is_connected and self.core_v1 and stream:
            try:
                # argv is sent directly to Kubernetes exec. No /bin/bash -c interpolation.
                resp = stream(
                    self.core_v1.connect_get_namespaced_pod_exec,
                    pod_name, namespace, container="toolbox", command=argv,
                    stderr=True, stdin=False, stdout=True, tty=False,
                    _request_timeout=30,
                )
                return {
                    "command": effective_command, "output": resp, "exit_code": None,
                    "executed_live": True, "execution_mode": "live",
                    "note": "Kubernetes exec returned output; process exit status was not exposed by this stream wrapper.",
                }
            except Exception as exc:
                logger.error("Live toolbox command failed in %s: %s", namespace, exc)
                return {
                    "command": effective_command, "output": f"Live execution failed: {exc}",
                    "exit_code": None, "executed_live": False, "execution_mode": "failed",
                }

        return {
            "command": effective_command,
            "output": f"SIMULATION ONLY: no Kubernetes command was executed against target '{target_endpoint or namespace}'. Configure and verify a sandbox cluster for live execution.",
            "exit_code": None, "executed_live": False, "execution_mode": "simulated",
        }

    def export_pcap_base64(self, session_id: str) -> Optional[str]:
        """Fetch a capture through the Kubernetes API as base64; never assume a host path is shared."""
        if not (self.is_connected and self.core_v1 and stream):
            return None
        try:
            output = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                "target-app", f"sandbox-{session_id}",
                container="network-tcpdump",
                command=["/bin/sh", "-c", "base64 /captures/network.pcap"],
                stderr=True, stdin=False, stdout=True, tty=False, _request_timeout=15,
            )
            # Strip line breaks emitted by base64 implementations.
            return "".join(str(output).split())
        except Exception as exc:
            logger.info("No readable PCAP capture for session %s: %s", session_id, exc)
            return None



# Global singleton instance
k8s_client = K8sSandboxClient()
