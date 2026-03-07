.PHONY: all lint format test test-podman tach security docstrings complexity deadcode reuse check install install-dev docs docs-build clean spdx

all: check

# Run linter and format checker (fast, run before commits)
lint:
	poetry run ruff check .
	poetry run ruff format --check .

# Auto-fix lint issues and format code
format:
	poetry run ruff check --fix .
	poetry run ruff format .

# Run tests with coverage (excludes integration tests)
test:
	poetry run pytest --cov=terok_shield --cov-report=term-missing --ignore=tests/integration
	@echo "NOTE: This security-critical package targets 100% test coverage."

# Run integration tests against real podman (requires podman + nft on host)
test-podman:
	poetry run pytest tests/integration/ -v -m integration

# Check module boundary rules (tach.toml)
tach:
	poetry run tach check

# Run SAST security scan on shield module
security:
	poetry run bandit -r src/terok_shield/ -ll

# Check docstring coverage (minimum 95%)
docstrings:
	poetry run docstr-coverage src/terok_shield/ --fail-under=95

# Check cognitive complexity (advisory — lists functions exceeding threshold)
complexity:
	poetry run complexipy src/terok_shield/ --max-complexity-allowed 15 --failed; true

# Find dead code (cross-file, min 80% confidence)
deadcode:
	poetry run vulture src/terok_shield/ vulture_whitelist.py --min-confidence 80

# Check REUSE (SPDX license/copyright) compliance
reuse:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	poetry run reuse lint

# Add SPDX header to files.
# NAME must be the real name of the person responsible for creating the file (not a project name).
# Example: make spdx NAME="Real Human Name" FILES="src/terok_shield/foo.py"
spdx:
ifndef NAME
	$(error NAME is required — use the real name of the copyright holder, e.g. make spdx NAME="Real Human Name" FILES="src/terok_shield/foo.py")
endif
	poetry run reuse annotate --template compact --copyright "$(NAME)" --license Apache-2.0 $(FILES)

# Run all checks (equivalent to CI)
check: lint test tach security docstrings deadcode reuse

# Install runtime dependencies only
install:
	poetry install --only main

# Install all dependencies (dev, test, docs)
install-dev:
	poetry install --with dev,test,docs

# Build documentation locally
docs:
	poetry run mkdocs serve

# Build documentation for deployment
docs-build:
	poetry run mkdocs build --strict

# Clean build artifacts
clean:
	rm -rf dist/ build/ site/ .coverage coverage.xml .pytest_cache/ .ruff_cache/ .complexipy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
