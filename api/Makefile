.PHONY: all build run test test-db lint clean docker-build docker-dev docker-prod docker-down migrate generate seed help seed-required docker-seed docker-seed-required db-setup db-setup-dev swagger contract swagger-check swagger-install

# Variables
APP_NAME := openctem
BUILD_DIR := bin
MAIN_PATH := cmd/server/main.go
COMPOSE_BASE := docker-compose.yml
COMPOSE_DEV := docker-compose.dev.yml

# Load .env file if exists
ifneq (,$(wildcard ./.env))
	include .env
	export
endif

# Database config (from environment or .env file)
DB_HOST ?= localhost
DB_PORT ?= 5432
DB_USER ?=
DB_PASSWORD ?=
DB_NAME ?= openctem
DB_SSLMODE ?= disable
DATABASE_URL ?= postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSLMODE)

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GORUN := $(GOCMD) run
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt

# Build flags
LDFLAGS := -ldflags "-s -w"

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## all: Build the application
all: lint test build

## build: Build the binary
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(APP_NAME)"

## run: Run the application
run:
	@echo "Running $(APP_NAME)..."
	$(GORUN) $(MAIN_PATH)

# DB-backed tests write and delete rows, so they never take DATABASE_URL from
# .env (that is the dev or live database). `make test` runs them only when
# TEST_DATABASE_URL names a *_test database; `make test-db` requires it.
TEST_DATABASE_URL ?=

## test: Run tests (DB-backed tests skip unless TEST_DATABASE_URL is set)
test:
	@echo "Running tests..."
	@if [ -z "$(TEST_DATABASE_URL)" ]; then echo "NOTE: TEST_DATABASE_URL is unset: DB-backed tests are SKIPPED (use make test-db)."; fi
	DATABASE_URL="$(TEST_DATABASE_URL)" $(GOTEST) -v -race -cover ./...

## test-db: Run all tests against TEST_DATABASE_URL (a migrated *_test database); nothing skips
test-db:
	@if [ -z "$(TEST_DATABASE_URL)" ]; then echo "TEST_DATABASE_URL is required, e.g. postgres://postgres@localhost:55432/app_test?sslmode=disable"; exit 1; fi
	DATABASE_URL="$(TEST_DATABASE_URL)" OPENCTEM_TEST_DB_REQUIRED=1 $(GOTEST) -race -timeout 20m ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	DATABASE_URL="$(TEST_DATABASE_URL)" $(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## test-load: Run load tests for platform queue
test-load:
	@echo "Running load tests..."
	$(GOTEST) -v -timeout=30m ./tests/load/...

## test-load-bench: Run load test benchmarks
test-load-bench:
	@echo "Running load test benchmarks..."
	$(GOTEST) -v -bench=. -benchmem -timeout=10m ./tests/load/...

# golangci-lint is pinned to v1.64.8: the repo's .golangci.yml is v1-format, and
# the current v2.x releases both reject that config AND panic analyzing this
# codebase under Go 1.26. `go run @version` ignores whatever is on PATH, so the
# target works regardless of any globally-installed (v2) binary.
GOLANGCI_LINT_VERSION ?= v1.64.8
GOLANGCI_LINT := go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

## lint: Run linter (golangci-lint, pinned) over the whole tree.
lint:
	@echo "Running golangci-lint $(GOLANGCI_LINT_VERSION)..."
	@GOWORK=off $(GOLANGCI_LINT) run ./...

## lint-new: golangci-lint on code this branch adds, which is what CI gates on.
## develop carries pre-existing findings; this freezes that debt instead of
## blocking every PR on it. BASE_REF defaults to origin/develop.
BASE_REF ?= origin/develop
lint-new:
	@echo "Running golangci-lint $(GOLANGCI_LINT_VERSION) against $(BASE_REF)..."
	@GOWORK=off $(GOLANGCI_LINT) run --new-from-rev=$(BASE_REF) ./...

## lint-ci: Run exactly what CI's Lint job gates on (go vet + staticcheck + lint-new).
## The whole point of this target is that it IS what CI runs — nothing else uses
## it. If you add a step to the Lint job, add it here in the same commit.
lint-ci: lint-new
	@echo "Running go vet..."
	@GOWORK=off go vet ./...
	@echo "Running staticcheck..."
	@GOWORK=off go run honnef.co/go/tools/cmd/staticcheck@latest ./...

## release-branch: build a release branch that can merge into main (VERSION=v0.5.0)
## Releases are squash-merged, so main ends up single-parent and git stops seeing
## that develop contains it — the next release then reports conflicts that are not
## disagreements. This carries the ancestry inside the branch instead, so it merges
## cleanly regardless of which button is pressed. Add PUSH=--push when ready.
release-branch:
	@bash scripts/release-branch.sh $(VERSION) $(PUSH)

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## tidy: Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

## swagger: Generate api/openapi/swagger.yaml from the handler annotations.
## The spec is generated and NOT committed (nor hand-edited): CI, release
## builds and `make generate` at the repository root produce it, and
## scripts/check-openapi.sh fails CI when the annotations, the spec and the
## registered routes stop agreeing.
swagger: swagger-install
	@echo "Generating Swagger documentation..."
	@# --parseDependency walks into dependency packages — the asset-type enum
	@# descriptions come from github.com/openctemio/ctis, not from this module,
	@# and without the flag swag fails outright on json.RawMessage. Download
	@# first so it is reading source rather than guessing.
	@#
	@# This does NOT make swag reproducible: a clean runner still drops
	@# `format: int64` from some map[string]int64 fields that a developer
	@# machine emits, with the same swag, the same Go and a warm cache. That is
	@# why the gate compares sets of operations rather than bytes. See
	@# tools/lint/openapicontract.
	@GOWORK=off go mod download
	@# The list query params come from the field registries (RFC-048).
	@GOWORK=off go run ./tools/gen/filterparams
	@GOWORK=off $(SWAG) init --generalInfo cmd/server/main.go --output api/openapi --outputTypes yaml --parseDependency
	@echo "Swagger docs generated in api/openapi/"

## contract: Generate every contract file derived from the Go source. None of
## them is committed:
##   api/openapi/swagger.yaml                    the OpenAPI spec (swagger)
##   api/openapi/routes.txt                      every registered route (web endpoint check)
##   ../web/src/config/api-route-permissions.json  the web console's route gate map
##   ../web/src/config/authz-matrix.json           the authorization reference (roles,
##                                                 templates, per-feature gates)
## The web API types are generated from the spec by `npm run generate:api-types`
## in web/; `make generate` at the repository root runs both halves.
contract: swagger
	@GOWORK=off UPDATE_ROUTE_MANIFEST=1 go test ./tools/lint/openapicontract/ -run '^TestWriteRouteManifest$$' -count=1 >/dev/null
	@GOWORK=off UPDATE_ROUTE_PERMISSIONS=1 go test ./tests/unit -run '^TestRoutePermissionMap$$' -count=1 >/dev/null
	@GOWORK=off go run ./cmd/gen-authz-docs
	@echo "Route manifest, route permission map and authorization reference generated"

## authz-docs: Write the authorization reference as markdown pages into DIR
##             (the documentation site adds FRONT_MATTER=1)
authz-docs:
	@test -n "$(DIR)" || { echo "usage: make authz-docs DIR=<output dir> [FRONT_MATTER=1]" >&2; exit 2; }
	@GOWORK=off go run ./cmd/gen-authz-docs -json "" -md "$(DIR)" $(if $(FRONT_MATTER),-front-matter,)

## swagger-check: Generate the spec, then fail if the annotations, the spec and
## the routes disagree. Compares SETS of operations, not bytes — see
## tools/lint/openapicontract for why.
swagger-check:
	@bash scripts/check-openapi.sh

## swagger-install: Install the pinned swag CLI (no-op if already present).
## Pinned: an upstream release must not be able to change the generated contract
## or turn every PR red. Bump here and in scripts/check-openapi.sh together.
SWAG_VERSION ?= v1.16.4
SWAG := $(shell command -v swag 2>/dev/null || echo "$$(go env GOPATH)/bin/swag")
swagger-install:
	@if ! "$(SWAG)" --version 2>/dev/null | grep -qF "$(SWAG_VERSION)"; then \
		echo "Installing swag $(SWAG_VERSION)..."; \
		GOWORK=off GOFLAGS=-mod=mod go install github.com/swaggo/swag/cmd/swag@$(SWAG_VERSION); \
	fi

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

## docker-build: Build Docker image (production)
docker-build:
	@echo "Building production Docker image..."
	docker build --target production -t $(APP_NAME):latest .

## docker-build-dev: Build Docker image (development)
docker-build-dev:
	@echo "Building development Docker image..."
	docker build --target development -t $(APP_NAME):dev .

## docker-dev: Start development environment with hot reload
docker-dev:
	@echo "Starting development environment..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) up --build

## docker-dev-d: Start development environment in background
docker-dev-d:
	@echo "Starting development environment (detached)..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) up -d --build

## docker-prod: Production runs from api/deploy (one HTTPS port): see its docker-compose.yml
docker-prod:
	@echo "Production deployment, from the repository root: cd api/deploy && cp .env.example .env && docker compose up -d"

## docker-down: Stop all Docker Compose services
docker-down:
	@echo "Stopping services..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) down 2>/dev/null || true

## docker-logs: View Docker Compose logs
docker-logs:
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) logs -f

## docker-logs-app: View only app logs
docker-logs-app:
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) logs -f app

## docker-ps: Show running containers
docker-ps:
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) ps

## docker-clean: Remove all containers, volumes, and images
docker-clean:
	@echo "Cleaning Docker resources..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) down -v --rmi local 2>/dev/null || true

## migrate-up: Run database migrations (local)
migrate-up:
	@echo "Running migrations..."
	@if [ -z "$(DB_USER)" ] || [ -z "$(DB_PASSWORD)" ]; then \
		echo "Error: DB_USER and DB_PASSWORD required. Set in .env or environment"; \
		exit 1; \
	fi
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path migrations -database "$(DATABASE_URL)" up; \
	else \
		echo "migrate not installed. Run: make install-tools"; \
		exit 1; \
	fi

## migrate-down: Rollback database migrations (local)
migrate-down:
	@echo "Rolling back migrations..."
	@if [ -z "$(DB_USER)" ] || [ -z "$(DB_PASSWORD)" ]; then \
		echo "Error: DB_USER and DB_PASSWORD required. Set in .env or environment"; \
		exit 1; \
	fi
	migrate -path migrations -database "$(DATABASE_URL)" down 1

## migrate-create: Create a new migration (usage: make migrate-create name=migration_name)
migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "Usage: make migrate-create name=migration_name"; \
		exit 1; \
	fi
	@echo "Creating migration $(name)..."
	migrate create -ext sql -dir migrations -seq $(name)

## migrate-status: Show migration status
migrate-status:
	@echo "Migration status..."
	migrate -path migrations -database "$(DATABASE_URL)" version

## docker-migrate-up: Run migrations using migrate docker image
docker-migrate-up:
	@echo "Running migrations..."
	docker run --rm -v $(PWD)/migrations:/migrations --network host \
		migrate/migrate -path=/migrations -database "$(DATABASE_URL)" up
	@echo "Migrations complete"

## docker-migrate-down: Rollback last migration using migrate docker image
docker-migrate-down:
	@echo "Rolling back last migration..."
	docker run --rm -v $(PWD)/migrations:/migrations --network host \
		migrate/migrate -path=/migrations -database "$(DATABASE_URL)" down 1

## docker-migrate-version: Show current migration version
docker-migrate-version:
	@docker run --rm -v $(PWD)/migrations:/migrations --network host \
		migrate/migrate -path=/migrations -database "$(DATABASE_URL)" version

## docker-migrate-force: Force set migration version (usage: make docker-migrate-force version=X)
docker-migrate-force:
	@if [ -z "$(version)" ]; then \
		echo "Usage: make docker-migrate-force version=X"; \
		exit 1; \
	fi
	docker run --rm -v $(PWD)/migrations:/migrations --network host \
		migrate/migrate -path=/migrations -database "$(DATABASE_URL)" force $(version)

## seed-required: Seed database with required data only (local)
seed-required:
	@echo "Seeding required data..."
	@if [ -z "$(DB_USER)" ] || [ -z "$(DB_PASSWORD)" ]; then \
		echo "Error: DB_USER and DB_PASSWORD required. Set in .env or environment"; \
		exit 1; \
	fi
	PGPASSWORD=$(DB_PASSWORD) psql -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) -d $(DB_NAME) -f migrations/seed/seed_required.sql

## docker-seed-required: Seed database with required data only (docker)
docker-seed-required:
	@echo "Seeding required data..."
	docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -f /dev/stdin < migrations/seed/seed_required.sql
	@echo "Required seed complete"

## docker-seed: Seed development data (required data; no users or organizations)
## Users and organizations come from bootstrap-admin (-org-name/-org-owner-email),
## as on a real install: see docs/development/migrations.md.
docker-seed: docker-seed-required

## docker-psql: Open psql shell in docker
docker-psql:
	docker compose -f $(COMPOSE_BASE) exec postgres psql -U $(DB_USER) -d $(DB_NAME)

## docker-reset-db: Reset database (drop and recreate)
docker-reset-db:
	@echo "Resetting database..."
	docker compose -f $(COMPOSE_BASE) exec postgres psql -U $(DB_USER) -d $(DB_NAME) -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@echo "Database reset. Run 'make docker-migrate-up' to apply migrations"

## db-setup: Setup database with schema only (migrate) in docker
db-setup: docker-migrate-up docker-seed-required
	@echo "Database setup complete (schema + required data)"

## db-setup-dev: Setup database with test data for development
db-setup-dev: docker-migrate-up docker-seed
	@echo "Development database setup complete (schema + all seed data)"

## db-fresh: Reset database and setup from scratch (for development)
db-fresh: docker-reset-db db-setup-dev
	@echo "Fresh database ready for development"

## generate: Generate code (mocks, protobuf)
generate:
	@echo "Generating code..."
	$(GOCMD) generate ./...

## generate-relationships: Regenerate relationship type files from YAML
##                         (Go enum + TS union + label/constraint maps)
##
## Single source of truth: configs/relationship-types.yaml
## Edit the YAML, run this target, commit YAML + the two generated files.
generate-relationships:
	@echo "Generating relationship types from configs/relationship-types.yaml..."
	@GOWORK=off $(GOCMD) run ./cmd/gen-relationships

## generate-modules: Regenerate the module registry (Go + TS) from YAML
##
## Single source of truth: configs/modules.yaml (RFC-064). Edit the YAML, run
## this target, commit YAML + the two generated files. If a catalog row
## changed (id, name, core, release, parent, order...), also add a migration
## whose body is `make modules-sql`.
generate-modules:
	@GOWORK=off $(GOCMD) run ./cmd/gen-modules

## modules-sql: Print the SQL block that writes the modules rows (the body of a registry migration)
modules-sql:
	@GOWORK=off $(GOCMD) run ./cmd/gen-modules -sql

## modules-check: Fail when the generated module files or the newest registry migration drifted
modules-check:
	@GOWORK=off $(GOCMD) run ./cmd/gen-modules -check

## generate-asset-types: Regenerate the asset type registry (Go + TS) from YAML
##
## Single source of truth: configs/asset-types.yaml (RFC-042 §6.3).
## Edit the YAML, run this target, commit YAML + the two generated files. If
## class, lens or alias data changed, also add a migration whose body is
## `make asset-types-sql`.
generate-asset-types:
	@GOWORK=off $(GOCMD) run ./cmd/gen-asset-types

## asset-types-sql: Print the SQL block that seeds asset_types and re-derives
##                  assets.asset_class / asset_lens (the body of a registry migration)
asset-types-sql:
	@GOWORK=off $(GOCMD) run ./cmd/gen-asset-types -sql

## asset-types-check: Fail if the YAML, the generated files or the newest
##                    registry migration block disagree (CI: Asset Types Drift)
asset-types-check:
	@GOWORK=off $(GOCMD) run ./cmd/gen-asset-types -check

## proto: Regenerate the sensor protocol v3 Go code (api/pkg/sensorproto/v3)
##        from api/proto with pinned buf and plugins (commit the result)
proto:
	@bash scripts/check-proto.sh --generate

## proto-check: buf lint, buf breaking against develop, generated code current
##              (CI: Sensor Protocol v3)
proto-check:
	@bash scripts/check-proto.sh

## dev: Run with hot reload (requires air)
dev:
	@if command -v air >/dev/null 2>&1; then \
		air; \
	else \
		echo "air not installed. Run: go install github.com/air-verse/air@latest"; \
		echo "Falling back to normal run..."; \
		$(MAKE) run; \
	fi

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/air-verse/air@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install go.uber.org/mock/mockgen@latest
	@echo "Tools installed"

# =============================================================================
# PRE-COMMIT & SECURITY
# =============================================================================

# Commit-time hooks are the repository's .githooks/ (root Makefile: `make hooks`).
# `pre-commit install` refuses to run while core.hooksPath is set, and would
# expect a .pre-commit-config.yaml at the repository root; the config in api/
# runs on demand with `make pre-commit-run`.
## pre-commit-install: Install the security tools and enable the repository git hooks (.githooks)
pre-commit-install:
	@echo "Installing security tools (pre-commit, betterleaks, trivy, hadolint)..."
	@if ! command -v pre-commit >/dev/null 2>&1; then \
		echo "Installing pre-commit..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			if ! command -v pip >/dev/null 2>&1; then \
				echo "Installing pip first..."; \
				sudo apt-get update && sudo apt-get install -y python3-pip; \
			fi; \
			pip install --break-system-packages pre-commit; \
		else \
			brew install pre-commit; \
		fi; \
	fi
	@if ! command -v go >/dev/null 2>&1; then \
		echo "Installing Go..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y golang-go; \
		else \
			brew install go; \
		fi; \
	fi
	@if ! command -v betterleaks >/dev/null 2>&1; then \
		echo "Installing betterleaks..."; \
		go install github.com/betterleaks/betterleaks@v1.9.0; \
	fi
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "Installing trivy..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y wget apt-transport-https gnupg lsb-release && \
			wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
			echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $$(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list && \
			sudo apt-get update && sudo apt-get install -y trivy; \
		else \
			brew install trivy; \
		fi; \
	fi
	@if ! command -v hadolint >/dev/null 2>&1; then \
		echo "Installing hadolint..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			wget -O /tmp/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 && \
			chmod +x /tmp/hadolint && sudo mv /tmp/hadolint /usr/local/bin/hadolint; \
		else \
			brew install hadolint; \
		fi; \
	fi
	git config core.hooksPath .githooks
	@echo "Tools installed; git hooks enabled (.githooks). Run the full hook set with: make pre-commit-run"

## pre-commit-run: Run all pre-commit hooks on all files
pre-commit-run:
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files

## pre-commit-update: Update pre-commit hooks to latest versions
pre-commit-update:
	@echo "Updating pre-commit hooks..."
	pre-commit autoupdate

## security-scan: Run full security scan (betterleaks + gosec + trivy)
security-scan:
	@echo "Running full security scan..."
	@echo "=== Betterleaks (Secret Detection) ==="
	@betterleaks git . --config .betterleaks.toml --redact --verbose || true
	@echo ""
	@echo "=== Golangci-lint with Gosec (Code Security) ==="
	@GOWORK=off $(GOLANGCI_LINT) run --config .golangci.yml ./... || true
	@echo ""
	@echo "=== Trivy (Vulnerability Scan) ==="
	@trivy fs --severity HIGH,CRITICAL --scanners vuln,secret,misconfig --skip-files Dockerfile.seed --skip-files Dockerfile.migrations --config trivy.yaml . || true
	@echo ""
	@echo "Security scan complete!"

## secrets: Run betterleaks secret detection over the git history
secrets:
	@echo "Running betterleaks..."
	betterleaks git . --config .betterleaks.toml --redact --verbose

# =============================================================================
# TENANT MANAGEMENT
# =============================================================================

## assign-plan: Assign a plan to tenant (usage: make assign-plan tenant=<uuid> plan=enterprise)
assign-plan:
	@if [ -z "$(tenant)" ]; then \
		echo "Usage: make assign-plan tenant=<uuid> plan=<plan_slug>"; \
		echo ""; \
		echo "Available plans: free, team, business, enterprise"; \
		echo ""; \
		echo "Example:"; \
		echo "  make assign-plan tenant=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa plan=enterprise"; \
		exit 1; \
	fi
	@if [ -z "$(plan)" ]; then \
		echo "Error: plan is required"; \
		echo "Available plans: free, team, business, enterprise"; \
		exit 1; \
	fi
	@echo "Assigning $(plan) plan to tenant $(tenant)..."
	@docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -c \
		"UPDATE tenants SET plan_id = (SELECT id FROM plans WHERE slug = '$(plan)'), updated_at = NOW() WHERE id = '$(tenant)';"
	@echo ""
	@echo "Verifying assignment..."
	@docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -c \
		"SELECT t.id, t.name, t.slug, p.name as plan_name, p.slug as plan_slug FROM tenants t JOIN plans p ON t.plan_id = p.id WHERE t.id = '$(tenant)';"

## list-tenants: List all tenants with their plans
list-tenants:
	@docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -c \
		"SELECT t.id, t.name, t.slug, p.name as plan_name, p.slug as plan_slug FROM tenants t JOIN plans p ON t.plan_id = p.id ORDER BY t.name;"

## list-plans: List all available plans
list-plans:
	@docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -c \
		"SELECT id, name, slug, price_monthly FROM plans ORDER BY price_monthly;"
