.PHONY: all dev build start test lint format clean docker-dev docker-prod docker-down help install pre-commit-install validate

# Variables
APP_NAME := openctem-ui
COMPOSE_BASE := docker-compose.yml

# Node/npm commands
NPM := npm
NPM_RUN := $(NPM) run

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## all: Run validation (type-check, lint, format-check)
all: validate

## install: Install dependencies
install:
	@echo "Installing dependencies..."
	$(NPM) install
	@echo "Dependencies installed"

## dev: Start development server
dev:
	@echo "Starting development server..."
	$(NPM_RUN) dev

## build: Build production bundle
build:
	@echo "Building production bundle..."
	$(NPM_RUN) build

## start: Start production server
start:
	@echo "Starting production server..."
	$(NPM_RUN) start

## test: Run tests
test:
	@echo "Running tests..."
	$(NPM_RUN) test

## test-ui: Run tests with UI
test-ui:
	@echo "Running tests with UI..."
	$(NPM_RUN) test:ui

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(NPM_RUN) test:coverage

## test-watch: Run tests in watch mode
test-watch:
	@echo "Running tests in watch mode..."
	$(NPM_RUN) test:watch

## lint: Run linter
lint:
	@echo "Running linter..."
	$(NPM_RUN) lint

## lint-fix: Run linter with auto-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	$(NPM_RUN) lint:fix

## format: Format code
format:
	@echo "Formatting code..."
	$(NPM_RUN) format

## format-check: Check code formatting
format-check:
	@echo "Checking code formatting..."
	$(NPM_RUN) format:check

## type-check: Run TypeScript type checking
type-check:
	@echo "Running type checker..."
	$(NPM_RUN) type-check

## validate: Run all validation checks (type-check, lint, format-check)
validate:
	@echo "Running validation..."
	$(NPM_RUN) validate

## analyze: Analyze bundle size
analyze:
	@echo "Analyzing bundle..."
	$(NPM_RUN) analyze

## clean: Clean build artifacts and dependencies
clean:
	@echo "Cleaning..."
	@rm -rf .next
	@rm -rf node_modules
	@rm -rf out
	@rm -rf coverage
	@echo "Clean complete"

## docker-dev: Start development environment with Docker
docker-dev:
	@echo "Starting development environment..."
	docker compose -f $(COMPOSE_BASE) up --build

## docker-dev-d: Start development environment in background
docker-dev-d:
	@echo "Starting development environment (detached)..."
	docker compose -f $(COMPOSE_BASE) up -d --build

## docker-prod: Production runs from api/deploy (one HTTPS port): see its docker-compose.yml
docker-prod:
	@echo "Production deployment, from the repository root: cd api/deploy && cp .env.example .env && docker compose up -d"

## docker-down: Stop all Docker Compose services
docker-down:
	@echo "Stopping services..."
	docker compose -f $(COMPOSE_BASE) down 2>/dev/null || true

## docker-logs: View Docker Compose logs
docker-logs:
	docker compose -f $(COMPOSE_BASE) logs -f

## docker-ps: Show running containers
docker-ps:
	docker compose -f $(COMPOSE_BASE) ps

## docker-clean: Remove all containers, volumes, and images
docker-clean:
	@echo "Cleaning Docker resources..."
	docker compose -f $(COMPOSE_BASE) down -v --rmi local 2>/dev/null || true

# =============================================================================
# PRE-COMMIT & LINTING
# =============================================================================

## pre-commit-install: Enable the repository git hooks (.githooks, same as `make hooks` at the root)
pre-commit-install:
	git config core.hooksPath .githooks
	@echo "Git hooks enabled: .githooks/ at the repository root (pre-commit: type-check + lint-staged for web/)."

## husky-install: Kept for compatibility; installs deps, whose prepare script enables .githooks
husky-install:
	$(NPM) install
	@echo "Git hooks enabled: .githooks/ at the repository root (no Husky)."

## pre-commit-run: Run all pre-commit hooks (if configured)
pre-commit-run:
	@if [ -f ".pre-commit-config.yaml" ]; then \
		echo "Running pre-commit hooks..."; \
		pre-commit run --all-files; \
	else \
		echo "No .pre-commit-config.yaml found. This project uses Husky."; \
		echo "Run 'make validate' instead."; \
	fi

## release-branch: build a release branch that can merge into main (VERSION=v0.5.0)
##
## Releases here are squash-merged, which leaves main with a single parent so git
## cannot see that develop already contains it. The next release then reports
## dozens of phantom conflicts. That has happened four times across this repo and
## api. The script sidesteps the merge strategy instead of fighting it: the branch
## carries develop's tree byte-for-byte plus one `merge -s ours` commit recording
## main as a parent, so it merges cleanly whichever button anyone presses.
release-branch:
	@if [ -z "$(VERSION)" ]; then echo "usage: make release-branch VERSION=v0.5.0" >&2; exit 2; fi
	@bash scripts/release-branch.sh "$(VERSION)"
