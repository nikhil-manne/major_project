#!/usr/bin/env bash
set -uo pipefail

ok()   { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }
FAILED=0

echo "Checking Phase 0 Infrastructure..."

echo -n "Postgres: "
docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-cyberrange}" >/dev/null 2>&1 && ok "ready" || fail "not ready"

echo -n "Kafka: "
docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null | grep -q normalized.events && ok "topics exist" || fail "topics missing (run scripts/create-topics.sh)"

echo -n "OpenSearch: "
curl -sf localhost:9200/_cluster/health 2>/dev/null | jq -e '.status != "red"' >/dev/null 2>&1 && ok "cluster not red" || fail "unhealthy"

echo -n "Index template: "
curl -sf localhost:9200/_index_template/events-template >/dev/null 2>&1 && ok "template applied" || fail "template missing"

echo -n "Keycloak: "
curl -sf localhost:8080/realms/cyberrange >/dev/null 2>&1 && ok "realm reachable" || fail "realm cyberrange missing"

echo -n "MinIO: "
curl -sf localhost:9000/minio/health/live >/dev/null 2>&1 && ok "live" || fail "not live"

echo -n "Kubernetes: "
kubectl get nodes --no-headers 2>/dev/null | grep -qv NotReady && ok "nodes ready" || echo "  [WARN] cluster not running (needed for Phase 2+)"

exit $FAILED
