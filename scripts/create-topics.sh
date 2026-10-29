#!/usr/bin/env bash
set -euo pipefail

TOPICS=(raw.attack raw.network raw.host raw.soc normalized.events)

echo "Creating Kafka topics for Cyber Range..."
for t in "${TOPICS[@]}"; do
  docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists --topic "$t" \
    --partitions 3 --replication-factor 1
done

echo "Current topics in Kafka:"
docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
