.PHONY: install format lint typecheck security contracts test integration check helm terraform audit image run clean

install:
	uv sync

format:
	uv run black src tests
	uv run ruff check src tests --fix

lint:
	uv run ruff check src tests
	uv run black --check src tests

typecheck:
	uv run mypy

security:
	uv run python -m bandit -q -r src -c pyproject.toml

contracts:
	uv run python -m continuous_red_teaming.contracts --check

test:
	uv run pytest

integration:
	uv run pytest tests/integration -m integration --no-cov

check: lint typecheck security contracts test

helm:
	helm lint deployments/helm/continuous-red-teaming -f deployments/helm/continuous-red-teaming/ci/test-values.yaml
	@if helm template crt deployments/helm/continuous-red-teaming > /dev/null 2>&1; then \
		echo "chart rendered without required values"; exit 1; fi

terraform:
	terraform fmt -recursive -check deployments/terraform
	for c in aws azure gcp; do terraform -chdir=deployments/terraform/$$c init -backend=false -input=false && terraform -chdir=deployments/terraform/$$c validate; done

audit:
	uv export --frozen --no-dev --no-emit-project --no-hashes --format requirements-txt | grep -v '^agentic-core' > .audit-requirements.txt
	uvx pip-audit -r .audit-requirements.txt --no-deps --disable-pip
	rm -f .audit-requirements.txt

image:
	docker build -t continuous-red-teaming:dev .

run:
	docker compose up --build

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
