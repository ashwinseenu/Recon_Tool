.PHONY: install dev test lint docker
install:
	sudo ./scripts/install.sh
dev:
	python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
test:
	.venv/bin/python -m pytest -q tests
docker:
	docker compose up -d --build
