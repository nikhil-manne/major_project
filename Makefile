.PHONY: up down logs topics smoke cluster cluster-rm reset

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

topics:
	bash ./scripts/create-topics.sh

smoke:
	bash ./scripts/smoke-test.sh

cluster:
	k3d cluster create cyberrange --servers 1 --agents 1 --k3s-arg "--disable=traefik@server:0"

cluster-rm:
	k3d cluster delete cyberrange

reset:
	docker compose down -v && k3d cluster delete cyberrange || true
