.PHONY: all build run test lint clean docker-build docker-dev docker-prod docker-down migrate generate seed help seed-required seed-test docker-seed-required docker-seed-test docker-seed-vnsecurity docker-seed-all db-setup db-setup-dev

# Variables
APP_NAME := rediver
BUILD_DIR := bin
MAIN_PATH := cmd/server/main.go
COMPOSE_BASE := docker-compose.yml
COMPOSE_DEV := docker-compose.dev.yml
COMPOSE_PROD := docker-compose.prod.yml

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
DB_NAME ?= rediver
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

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
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

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		GOWORK=off golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## tidy: Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

## swagger: Generate OpenAPI documentation using swag
swagger:
	@echo "Generating Swagger documentation..."
	@if command -v swag >/dev/null 2>&1; then \
		GOWORK=off swag init --generalInfo cmd/server/main.go --output api/openapi --outputTypes yaml --parseDependency; \
		echo "" >> api/openapi/swagger.yaml; \
		echo "Swagger docs generated in api/openapi/"; \
	else \
		echo "swag not installed. Run: make swagger-install"; \
	fi

## swagger-install: Install swag CLI tool
swagger-install:
	@echo "Installing swag..."
	go install github.com/swaggo/swag/cmd/swag@latest

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

## docker-prod: Start production environment
docker-prod:
	@echo "Starting production environment..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_PROD) up -d --build

## docker-down: Stop all Docker Compose services
docker-down:
	@echo "Stopping services..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) down 2>/dev/null || true
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_PROD) down 2>/dev/null || true

## docker-logs: View Docker Compose logs
docker-logs:
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) logs -f 2>/dev/null || \
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_PROD) logs -f

## docker-logs-app: View only app logs
docker-logs-app:
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) logs -f app 2>/dev/null || \
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_PROD) logs -f app

## docker-ps: Show running containers
docker-ps:
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) ps 2>/dev/null || \
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_PROD) ps

## docker-clean: Remove all containers, volumes, and images
docker-clean:
	@echo "Cleaning Docker resources..."
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_DEV) down -v --rmi local 2>/dev/null || true
	docker compose -f $(COMPOSE_BASE) -f $(COMPOSE_PROD) down -v --rmi local 2>/dev/null || true

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

## docker-seed: Run the comprehensive seed script (Aliases to new standard)
docker-seed: docker-seed-comprehensive

## docker-seed-comprehensive: Run the comprehensive seed script (Tenants, Users, Assets, Findings)
docker-seed-comprehensive:
	@echo "Running comprehensive seed..."
	docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -f /dev/stdin < migrations/seed/seed_comprehensive.sql
	@echo "Comprehensive seed complete"

## docker-seed-access-control: Seed access control data (modules, permissions, permission sets)
docker-seed-access-control:
	@echo "Seeding access control data..."
	docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -f /dev/stdin < migrations/seed/seed_access_control.sql
	@echo "Access control seed complete"

## docker-seed-recommended-teams: Seed recommended teams for a tenant (requires tenant_id)
docker-seed-recommended-teams:
	@if [ -z "$(tenant_id)" ]; then \
		echo "Usage: make docker-seed-recommended-teams tenant_id=<uuid>"; \
		echo "Example: make docker-seed-recommended-teams tenant_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"; \
		exit 1; \
	fi
	@echo "Seeding recommended teams for tenant $(tenant_id)..."
	docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -f /dev/stdin < migrations/seed/seed_recommended_teams.sql
	docker compose -f $(COMPOSE_BASE) exec -T postgres psql -U $(DB_USER) -d $(DB_NAME) -c "SELECT * FROM seed_recommended_teams('$(tenant_id)');"
	@echo "Recommended teams seed complete"



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

## proto: Generate protobuf code
proto:
	@echo "Generating protobuf..."
	@if [ -d "api/proto" ]; then \
		protoc --go_out=. --go-grpc_out=. api/proto/*.proto; \
	else \
		echo "No proto files found in api/proto/"; \
	fi

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
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/air-verse/air@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install go.uber.org/mock/mockgen@latest
	@echo "Tools installed"

# =============================================================================
# PRE-COMMIT & SECURITY
# =============================================================================

## pre-commit-install: Install pre-commit hooks
pre-commit-install:
	@echo "Installing pre-commit hooks..."
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
	@if ! command -v gitleaks >/dev/null 2>&1; then \
		echo "Installing gitleaks..."; \
		go install github.com/zricethezav/gitleaks/v8@latest; \
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
	pre-commit install
	@echo "Pre-commit hooks installed successfully!"

## pre-commit-run: Run all pre-commit hooks on all files
pre-commit-run:
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files

## pre-commit-update: Update pre-commit hooks to latest versions
pre-commit-update:
	@echo "Updating pre-commit hooks..."
	pre-commit autoupdate

## security-scan: Run full security scan (gitleaks + gosec + trivy)
security-scan:
	@echo "Running full security scan..."
	@echo "=== Gitleaks (Secret Detection) ==="
	@gitleaks detect --config .gitleaks.toml --verbose || true
	@echo ""
	@echo "=== Golangci-lint with Gosec (Code Security) ==="
	@golangci-lint run --config .golangci.yml ./... || true
	@echo ""
	@echo "=== Trivy (Vulnerability Scan) ==="
	@trivy fs --severity HIGH,CRITICAL --scanners vuln,secret,misconfig --skip-files Dockerfile.seed --skip-files Dockerfile.migrations --config trivy.yaml . || true
	@echo ""
	@echo "Security scan complete!"

## gitleaks: Run gitleaks secret detection
gitleaks:
	@echo "Running gitleaks..."
	gitleaks detect --config .gitleaks.toml --verbose

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
