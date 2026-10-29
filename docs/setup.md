# Local Development Setup

Step-by-step guide to getting the platform's shared backbone (Kubernetes, Kafka, PostgreSQL, OpenSearch, Keycloak, MinIO) running on a teammate's laptop. Covers **Phase 0** of `plan.md`.

Goal: every teammate, on any OS, ends up with an **identical** environment after following this file once. If a step here is wrong or unclear, fix this file in the same PR as the fix. This document is the source of truth, not anyone's memory.

> **Scope:** This is a **dev-only** setup. Security is deliberately relaxed (plaintext Kafka, OpenSearch security plugin off, default passwords). Never reuse these settings anywhere reachable from a network you don't control. See `security-considerations.md` for what production-grade looks like.

---

## 1. What You Will End Up With

| Component | Where it runs | Host port | Purpose |
|---|---|---|---|
| Kubernetes (k3s via k3d) | Docker containers | 6443 (API) | Sandbox namespaces (Phase 2+) |
| Kafka (KRaft, single broker) | Docker Compose | 9092 | Event backbone |
| PostgreSQL 16 | Docker Compose | 5432 | Metadata, Sigma rules |
| OpenSearch 2.x | Docker Compose | 9200 | Event storage/search |
| OpenSearch Dashboards | Docker Compose | 5601 | Optional visualization |
| Keycloak 26 | Docker Compose | 8080 | Auth / RBAC |
| MinIO | Docker Compose | 9000 (API), 9001 (console) | Session archives |
| Kafka UI (optional) | Docker Compose (profile `tools`) | 8089 | Inspect topics while debugging |

**Design choice:** the *shared backbone* runs in Docker Compose (simple, fast to restart), while the *per-session sandboxes* run in Kubernetes (because namespace and NetworkPolicy isolation is the thing we're actually building and testing). Platform services (ingestion, orchestrator, etc.) run directly on your laptop during development and talk to both.

---

## 2. Hardware and OS Requirements

| | Minimum | Recommended |
|---|---|---|
| RAM | 16 GB | 32 GB |
| CPU | 4 cores | 8 cores |
| Free disk | 30 GB | 60 GB |
| Virtualization | Enabled in BIOS/UEFI | |

Rough baseline memory once everything is up: Kafka ~1 GB, OpenSearch ~1.5-2 GB, Keycloak ~0.7 GB, Postgres ~0.2 GB, MinIO ~0.2 GB, k3d cluster ~1.5 GB. That is **about 5-6 GB before any sandbox runs.** Phases 3-5 (toolbox pods, Falco, Suricata) add more. On a 16 GB laptop, close the browser tabs you don't need.

### OS-specific notes

- **Linux (Ubuntu 22.04/24.04):** Easiest path. Everything runs natively.
- **Windows:** Use **WSL2 (Ubuntu)**. Run *all* commands and keep the repo *inside the WSL filesystem* (`~/projects/...`), not under `/mnt/c/...`. Cross-filesystem I/O is very slow and breaks file watchers.
- **macOS:** Docker Desktop or Colima. Allocate at least 10 GB RAM to the VM. Apple Silicon works, but check that every image you pull has an `arm64` variant (all images in this file do).

> **Known limitation for later phases:** Falco (Phase 4) needs kernel-level access (eBPF). It generally works on native Linux and WSL2, but is unreliable on macOS Docker VMs. Plan to run Phase 4 work on a Linux or WSL2 machine, or a shared Linux VM, and agree as a team who owns that machine.

---

## 3. Install Prerequisites

Install these and check versions. Use **at least** these versions; if a teammate is on a different major version, that is the first thing to check when something behaves differently.

| Tool | Version | Check |
|---|---|---|
| Docker Engine / Desktop | 24+ | `docker --version` |
| Docker Compose v2 | 2.20+ | `docker compose version` |
| kubectl | 1.28+ | `kubectl version --client` |
| k3d | 5.6+ | `k3d version` |
| Helm | 3.12+ | `helm version` |
| Git | any recent | `git --version` |
| Python | 3.11+ | `python3 --version` |
| Node.js | 20 LTS | `node --version` |
| jq, curl | any | `jq --version` |

Ubuntu / WSL2 quick install (Docker Engine, not Desktop):

```bash
# Docker Engine + Compose plugin (official convenience script)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER     # then log out/in (or: newgrp docker)

# kubectl, helm, k3d
sudo snap install kubectl --classic
sudo snap install helm --classic
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# helpers
sudo apt-get update && sudo apt-get install -y jq curl git python3-venv
```

macOS (Homebrew):

```bash
brew install --cask docker           # or: brew install colima docker docker-compose
brew install kubectl helm k3d jq git python@3.11 node@20
```

> If you use Colima instead of Docker Desktop: `colima start --cpu 4 --memory 10 --disk 60`.

---

## 4. Kernel Setting Required by OpenSearch

OpenSearch will crash on startup with a `max virtual memory areas vm.max_map_count [65530] is too low` error unless this is raised.

**Linux:**
```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf   # persist
```

**WSL2:** run the first command inside WSL each boot, or persist it by adding this to `C:\Users\<you>\.wslconfig`, then run `wsl --shutdown`:
```ini
[wsl2]
memory=12GB
kernelCommandLine=sysctl.vm.max_map_count=262144
```

**macOS (Docker Desktop/Colima):** usually fine. If OpenSearch still exits with that error:
```bash
docker run --rm --privileged --pid=host alpine:3 nsenter -t 1 -m -u -n -i sysctl -w vm.max_map_count=262144
```

---

## 5. Get the Repo and Configure Environment

```bash
git clone <repo-url> cyber-range
cd cyber-range
cp .env.example .env
```

The expected repo layout (create the empty folders now if the repo doesn't have them yet):

```
cyber-range/
├── docker-compose.yml
├── .env.example            # committed
├── .env                    # NOT committed (in .gitignore)
├── Makefile
├── infra/
│   ├── postgres/init/01-create-dbs.sql
│   ├── keycloak/realm-export.json
│   ├── opensearch/index-template.json
│   └── k8s/                # namespaces, network policies (Phase 2)
├── scripts/
│   ├── create-topics.sh
│   └── smoke-test.sh
├── services/               # one folder per service (see requirements.md)
│   ├── ingestion-service/
│   ├── orchestrator/
│   └── ...
└── docs/                   # goal, plan, requirements, schema, architecture, ...
```

### `.env.example`

```bash
# --- PostgreSQL ---
POSTGRES_USER=cyberrange
POSTGRES_PASSWORD=dev_only_change_me
POSTGRES_DB=cyberrange

# --- Keycloak ---
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=dev_only_change_me
KEYCLOAK_DB_PASSWORD=dev_only_change_me

# --- MinIO ---
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=dev_only_change_me

# --- OpenSearch heap (raise to 2g if you have 32 GB RAM) ---
OPENSEARCH_HEAP=1g
```

`.env` must be in `.gitignore`. Only `.env.example` is committed, and it must contain **no real secrets**.

---

## 6. The Docker Compose File

Save as `docker-compose.yml` in the repo root. Versions are pinned on purpose: "latest" is how three laptops end up with three different environments.

```yaml
name: cyber-range

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
      KEYCLOAK_DB_PASSWORD: ${KEYCLOAK_DB_PASSWORD}
    ports: ["5432:5432"]
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./infra/postgres/init:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10

  kafka:
    image: apache/kafka:3.8.0
    ports: ["9092:9092"]
    environment:
      KAFKA_NODE_ID: 1
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093,INTERNAL://:29092
      # PLAINTEXT = for apps on your laptop; INTERNAL = for other containers
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092,INTERNAL://kafka:29092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,INTERNAL:PLAINTEXT
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      KAFKA_INTER_BROKER_LISTENER_NAME: INTERNAL
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
      KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS: 0
    volumes:
      - kafkadata:/var/lib/kafka/data
    healthcheck:
      test: ["CMD-SHELL", "/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 > /dev/null 2>&1"]
      interval: 10s
      timeout: 10s
      retries: 10

  opensearch:
    image: opensearchproject/opensearch:2.17.1
    environment:
      discovery.type: single-node
      DISABLE_SECURITY_PLUGIN: "true"      # DEV ONLY
      DISABLE_INSTALL_DEMO_CONFIG: "true"
      OPENSEARCH_JAVA_OPTS: "-Xms${OPENSEARCH_HEAP:-1g} -Xmx${OPENSEARCH_HEAP:-1g}"
    ulimits:
      memlock: { soft: -1, hard: -1 }
      nofile: { soft: 65536, hard: 65536 }
    ports: ["9200:9200"]
    volumes:
      - osdata:/usr/share/opensearch/data
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health || exit 1"]
      interval: 10s
      timeout: 10s
      retries: 15

  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:2.17.1
    environment:
      OPENSEARCH_HOSTS: '["http://opensearch:9200"]'
      DISABLE_SECURITY_DASHBOARDS_PLUGIN: "true"
    ports: ["5601:5601"]
    depends_on:
      opensearch: { condition: service_healthy }

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    command: ["start-dev", "--import-realm"]
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: ${KEYCLOAK_ADMIN}
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KEYCLOAK_DB_PASSWORD}
      KC_HEALTH_ENABLED: "true"
    ports: ["8080:8080"]
    volumes:
      - ./infra/keycloak:/opt/keycloak/data/import:ro
    depends_on:
      postgres: { condition: service_healthy }

  minio:
    image: minio/minio:latest        # pin to a RELEASE tag once the team picks one
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    ports: ["9000:9000", "9001:9001"]
    volumes:
      - miniodata:/data

  kafka-ui:
    profiles: ["tools"]
    image: provectuslabs/kafka-ui:latest
    environment:
      KAFKA_CLUSTERS_0_NAME: local
      KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: kafka:29092
    ports: ["8089:8080"]
    depends_on:
      kafka: { condition: service_healthy }

volumes:
  pgdata:
  kafkadata:
  osdata:
  miniodata:
```

### `infra/postgres/init/01-create-dbs.sql`

Postgres runs this once, on first start of an empty volume. It creates the separate database and user Keycloak needs.

```sql
CREATE USER keycloak WITH PASSWORD 'dev_only_change_me';
CREATE DATABASE keycloak OWNER keycloak;
```

> The password here must match `KEYCLOAK_DB_PASSWORD` in `.env`. (Init SQL files can't read env vars, so keep the dev default identical in both places, or convert this file to a `.sh` init script that uses `$KEYCLOAK_DB_PASSWORD`.)

---

## 7. Start the Backbone

```bash
docker compose up -d
docker compose ps          # wait until postgres, kafka, opensearch show "healthy"
```

First start pulls several GB of images and takes a few minutes. OpenSearch is typically the slowest to become healthy (up to ~60 seconds after the container starts).

Optional Kafka UI: `docker compose --profile tools up -d kafka-ui`, then open http://localhost:8089.

### Create the Kafka topics

Topic names come from `architecture.md`. Save as `scripts/create-topics.sh` and make it executable (`chmod +x`).

```bash
#!/usr/bin/env bash
set -euo pipefail
TOPICS=(raw.attack raw.network raw.host raw.soc normalized.events)
for t in "${TOPICS[@]}"; do
  docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists --topic "$t" \
    --partitions 3 --replication-factor 1
done
docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
```

### Create the MinIO bucket

Open http://localhost:9001, log in with the `.env` credentials, and create a bucket named `sessions`. Or from the CLI:

```bash
docker run --rm --network host --entrypoint sh minio/mc -c \
  "mc alias set local http://localhost:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD && mc mb --ignore-existing local/sessions"
```

### Create the OpenSearch index template

The normalized event schema (`schema.md`) needs explicit mappings. Without them, OpenSearch guesses types, and `timestamp` or `mitre_technique` will be mapped wrongly in ways that are painful to fix later. Save as `infra/opensearch/index-template.json`:

```json
{
  "index_patterns": ["events-*"],
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "dynamic": "true",
      "properties": {
        "event_id":        { "type": "keyword" },
        "tenant_id":       { "type": "keyword" },
        "session_id":      { "type": "keyword" },
        "scenario_id":     { "type": "keyword" },
        "build_id":        { "type": "keyword" },
        "timestamp":       { "type": "date" },
        "source_type":     { "type": "keyword" },
        "source_name":     { "type": "keyword" },
        "actor":           { "type": "keyword" },
        "action":          { "type": "text", "fields": { "raw": { "type": "keyword", "ignore_above": 1024 } } },
        "mitre_tactic":    { "type": "keyword" },
        "mitre_technique": { "type": "keyword" },
        "severity":        { "type": "keyword" },
        "outcome":         { "type": "keyword" },
        "replay":          { "type": "boolean" },
        "raw_payload":     { "type": "object", "enabled": false }
      }
    }
  }
}
```

Apply it:

```bash
curl -s -X PUT localhost:9200/_index_template/events-template \
  -H 'Content-Type: application/json' \
  -d @infra/opensearch/index-template.json
```

> `raw_payload` is stored but not indexed (`enabled: false`) because it is arbitrary tool output with unpredictable shape. If the Detection Engine needs to match on fields inside it, replace this with a `flattened` type or targeted sub-field mappings. **Any change here is a schema change.** Follow the Schema Change Policy in `schema.md`.

---

## 8. Configure Keycloak (Once, Then Share via Export)

Keycloak state lives in each laptop's Postgres volume, so three people clicking through the admin console will produce three slightly different setups. To avoid this, **one person** configures it, exports it, and commits `infra/keycloak/realm-export.json`. Everyone else gets it automatically through `--import-realm`.

### 8a. If `infra/keycloak/realm-export.json` already exists in the repo

Nothing to do. `docker compose up -d` already imported it. Skip to 8c. (The import only runs if the realm doesn't exist yet. To pick up a changed export, see "Reset everything" in Section 12.)

### 8b. If you are the person creating it (first time only)

Open http://localhost:8080 and log in with `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`.

1. **Create realm** named `cyberrange`.
2. **Realm roles:** create `red`, `blue`, `soc`, `admin`. (`schema.md` uses lowercase; keep it consistent.)
3. **User attribute for tenant:** Realm settings → User profile → add attribute `tenant_id`.
4. **Client scope:** Client scopes → create `cyberrange-claims` (type: Default), then add two mappers:
   - *User Attribute*: user attribute `tenant_id` → token claim `tenant_id` (add to access token).
   - *User Realm Role*: token claim name `role` (add to access token). This gives you the `role` claim `architecture.md` expects.
5. **Client** `cyberrange-web`: public client, Standard flow + PKCE, valid redirect URIs `http://localhost:3000/*` (React dev server), web origins `http://localhost:3000`. Attach the `cyberrange-claims` scope.
6. **Dev-only test client** `cyberrange-dev-cli`: confidential or public, Direct access grants **on**. This lets you fetch tokens with `curl` for API testing. Remove it before any real deployment.
7. **Test users**, all with `tenant_id = 00000000-0000-0000-0000-000000000123`, password `dev_only_change_me`, and the role matching their name:

   | Username | Role |
   |---|---|
   | `red1` | red |
   | `blue1` | blue |
   | `soc1` | soc |
   | `admin1` | admin |

   Add one more user, `other_tenant_user`, with `tenant_id = org-999` and role `blue`. You will need it to **test that tenant isolation actually works** (see `security-considerations.md`).
8. **Export:** Realm settings → Action → Partial export (include groups/roles, clients). Or from the CLI:
   ```bash
   docker compose exec keycloak /opt/keycloak/bin/kc.sh export \
     --dir /tmp/export --realm cyberrange --users realm_file
   docker compose cp keycloak:/tmp/export/cyberrange-realm.json infra/keycloak/realm-export.json
   ```
   Commit it. Make sure it contains only the dev test users and dev passwords.

### 8c. Verify tokens carry the right claims

```bash
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/cyberrange/protocol/openid-connect/token \
  -d grant_type=password -d client_id=cyberrange-dev-cli \
  -d username=red1 -d password=dev_only_change_me | jq -r .access_token)

echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{tenant_id, role, preferred_username}'
```

You should see `tenant_id: "00000000-0000-0000-0000-000000000123"` and the `red` role. If `tenant_id` is missing, the attribute mapper or client-scope assignment from step 4 is the usual culprit.

---

## 9. Local Kubernetes Cluster (k3d)

We use **k3d** (k3s running inside Docker) because it works identically on Linux, macOS, and WSL2 and can be deleted and recreated in seconds.

```bash
k3d cluster create cyberrange \
  --servers 1 --agents 1 \
  --k3s-arg "--disable=traefik@server:0"

kubectl config use-context k3d-cyberrange
kubectl get nodes          # both nodes should be Ready
```

**Native Linux alternative (real k3s, no Docker layer):**
```bash
curl -sfL https://get.k3s.io | sh -s - --disable traefik --write-kubeconfig-mode 644
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

**minikube alternative:** works, but you **must** start it with a CNI that enforces NetworkPolicy, otherwise isolation silently does nothing:
```bash
minikube start --cpus 4 --memory 6144 --cni=calico
```

### Verify NetworkPolicy is actually enforced (do not skip)

The entire sandbox isolation claim rests on this. A cluster that accepts NetworkPolicy objects but doesn't enforce them looks identical to one that does, until you test it.

```bash
kubectl create namespace np-test
kubectl -n np-test run server --image=nginx --port=80
kubectl -n np-test expose pod server --port=80
kubectl -n np-test run client --image=busybox --restart=Never -- sleep 3600
kubectl -n np-test wait --for=condition=Ready pod/server pod/client --timeout=120s

# 1. Before the policy: should succeed
kubectl -n np-test exec client -- wget -qO- --timeout=3 http://server | head -n1

# 2. Apply default-deny ingress
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-ingress, namespace: np-test }
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF

# 3. After the policy: should FAIL (timeout). If it still succeeds, enforcement is broken.
kubectl -n np-test exec client -- wget -qO- --timeout=3 http://server || echo "BLOCKED (good)"

kubectl delete namespace np-test
```

Every teammate runs this once. If step 3 doesn't print `BLOCKED (good)`, stop and fix it before starting Phase 2.

### Reaching host services from inside the cluster

Pods in k3d reach services on your laptop through `host.k3d.internal` (k3d adds this automatically). For example, a sidecar forwarding to Kafka uses `host.k3d.internal:9092`. If you ever need to use this on minikube, it's `host.minikube.internal`. Keep the broker address in config, never hardcoded.

---

## 10. Smoke Test: "Is Phase 0 Done?"

Save as `scripts/smoke-test.sh`. Everyone runs it after setup and before asking for help.

```bash
#!/usr/bin/env bash
set -uo pipefail
ok()   { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }
FAILED=0

echo "Postgres";   docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-cyberrange}" >/dev/null && ok "ready" || fail "not ready"
echo "Kafka";      docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list | grep -q normalized.events && ok "topics exist" || fail "topics missing (run scripts/create-topics.sh)"
echo "OpenSearch"; curl -sf localhost:9200/_cluster/health | jq -e '.status != "red"' >/dev/null && ok "cluster not red" || fail "unhealthy"
echo "Index template"; curl -sf localhost:9200/_index_template/events-template >/dev/null && ok "template applied" || fail "template missing"
echo "Keycloak";   curl -sf localhost:8080/realms/cyberrange >/dev/null && ok "realm reachable" || fail "realm cyberrange missing"
echo "MinIO";      curl -sf localhost:9000/minio/health/live >/dev/null && ok "live" || fail "not live"
echo "Kubernetes"; kubectl get nodes --no-headers 2>/dev/null | grep -qv NotReady && ok "nodes ready" || fail "cluster not ready"

exit $FAILED
```

When everything passes, you have met the Phase 0 deliverable: infra up, login works, schema documented.

---

## 11. Daily Workflow

A `Makefile` saves everyone from memorizing commands:

```makefile
up:        ; docker compose up -d
down:      ; docker compose down
logs:      ; docker compose logs -f --tail=100
topics:    ; ./scripts/create-topics.sh
smoke:     ; ./scripts/smoke-test.sh
cluster:   ; k3d cluster create cyberrange --servers 1 --agents 1 --k3s-arg "--disable=traefik@server:0"
cluster-rm:; k3d cluster delete cyberrange
reset:     ; docker compose down -v && k3d cluster delete cyberrange || true
```

- **Stopping for the day:** `make down` (keeps data). Stop the cluster with `k3d cluster stop cyberrange`.
- **Starting again:** `make up`, then `k3d cluster start cyberrange`.

---

## 12. Team Conventions

1. **Pin versions.** If you bump an image tag in `docker-compose.yml`, say so in the PR so everyone re-pulls.
2. **Never commit `.env`**, kubeconfigs, or exports containing real credentials.
3. **The schema is shared.** Changes to `schema.md`, the OpenSearch index template, or the Keycloak realm export go through a PR that all three people see, because they break everyone's local data.
4. **Reset everything** when something is truly stuck or after pulling a changed Keycloak export or index template:
   ```bash
   make reset && make up && make topics
   # then re-apply the index template and recreate the MinIO bucket (Section 7)
   ```
   Consider scripting the template and bucket steps into `make bootstrap` once the team agrees they're stable.
5. **Two-person phases (3 and 4):** agree on the `raw.*` message shapes in `schema.md` *before* splitting up, so each person can mock the other's output with `kafka-console-producer` while the other half isn't ready.
6. **Document surprises here.** If you hit a problem that cost you more than 15 minutes, add it to Troubleshooting.

---

## 13. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| OpenSearch exits immediately, log mentions `vm.max_map_count` | Kernel setting too low | Section 4 |
| OpenSearch container killed (exit 137) | Out of memory | Lower `OPENSEARCH_HEAP`, raise Docker's RAM limit, close other apps |
| Kafka client connects but then fails with `localhost:29092` or `kafka:29092` errors | Using the wrong listener | From your laptop use `localhost:9092`. From other containers use `kafka:29092`. From k3d pods use `host.k3d.internal:9092` |
| Keycloak: `database "keycloak" does not exist` | Postgres init script didn't run (volume already existed) | `docker compose down -v` and start again, or create the DB manually |
| Keycloak realm missing after `up` | `realm-export.json` absent or malformed, or realm existed already | Check `docker compose logs keycloak`; see Section 12 reset |
| Token has no `tenant_id` | Mapper not attached to the client's scopes | Section 8b step 4 and 5 |
| `kubectl` says connection refused | Cluster stopped, or wrong context | `k3d cluster start cyberrange`; `kubectl config use-context k3d-cyberrange` |
| NetworkPolicy test doesn't block | CNI not enforcing | k3d/k3s: confirm you didn't pass `--disable-network-policy`. minikube: recreate with `--cni=calico` |
| WSL2: everything is very slow | Repo is on `/mnt/c/...` | Move it into the WSL home directory |
| Port already in use (5432, 8080, 9200...) | Local Postgres/other service running | Stop it, or change the host port in `docker-compose.yml` (left side of `"host:container"`) |
| Apple Silicon: `exec format error` | Image has no arm64 build | Add `platform: linux/amd64` to that service (slower), or find an arm64 image |

---

## 14. What Comes Later (Not Part of This Setup)

These are added in their own phases and are intentionally not in Phase 0:

- **Phase 2:** Orchestrator, Trivy, Hadolint, Kaniko, NetworkPolicy templates.
- **Phase 3:** Red team toolbox image (Nmap, Metasploit, sqlmap, ttyd, asciinema).
- **Phase 4:** Falco and Suricata (needs a Linux kernel with eBPF support; see Section 2).
- **Phase 8:** Claude API key for the copilot. Store it in `.env` as `ANTHROPIC_API_KEY`, never in the repo. Budget a small amount; or use Ollama for zero cost, as noted in `requirements.md`.
