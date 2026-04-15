# RFC-003: Monorepo Consolidation — Merge api + ui + agent into a single repository

- **Status**: Draft
- **Created**: 2026-04-15
- **Author**: OpenCTEM Team
- **Priority**: High
- **Estimated effort**: 1-2 days (migration), 1 day (CI/CD), 1 day (verification)

---

## Table of Contents

1. [Current State and Problems](#1-current-state-and-problems)
2. [Objectives](#2-objectives)
3. [Decision Analysis: What to Merge, What to Keep](#3-decision-analysis-what-to-merge-what-to-keep)
4. [Target Monorepo Structure](#4-target-monorepo-structure)
5. [Detailed Implementation Plan](#5-detailed-implementation-plan)
6. [CI/CD Design](#6-cicd-design)
7. [Docker & Development workflow](#7-docker--development-workflow)
8. [Go module strategy](#8-go-module-strategy)
9. [Risks and Mitigations](#9-risks-and-mitigations)
10. [Rollback plan](#10-rollback-plan)
11. [Implementation Checklist](#11-implementation-checklist)
12. [Open Questions](#12-open-questions)

---

## 1. Current State and Problems

### 1.1 Current Structure

```
openctemio/                    <- git repo (local only, NO remote)
├── .git/                      <- 10+ commits, previously tracked submodules
├── docker-compose.yml         <- orchestrates api + ui
├── go.work                    <- links api, agent, sdk-go
├── helm-charts/               <- separate git repo
├── docs/                      <- GitHub Pages (not tracked by any repo)
│
├── api/                       <- github.com/openctemio/api     (360 commits, 343MB)
│   └── .git/                  <- 34MB git history
├── ui/                        <- github.com/openctemio/ui      (354 commits, 1.6GB*)
│   └── .git/                  <- 17MB git history
├── agent/                     <- github.com/openctemio/agent   (39 commits, 2.9MB)
│   └── .git/                  <- 2.3MB git history
│
├── sdk-go/                    <- github.com/openctemio/sdk-go  (39 commits, published module)
├── ctis/                      <- github.com/openctemio/ctis    (2 commits, published module)
└── schemas/                   <- github.com/rediverio/schemas  (14 commits, deprecated)
```

*\* ui 1.6GB is mostly node_modules (gitignored). Actual source + .git is about 50MB.*

### 1.2 Specific Problems

#### P1: Atomic changes are impossible

When a feature requires changes to both API + UI (e.g., removing `metadata` column, adding sub_type, asset normalization):

```
Current (multi-repo):                     Desired (monorepo):
─────────────────────────                  ──────────────────────
1. Branch api/feat/xyz                     1. Branch feat/xyz
2. Branch ui/feat/xyz                      2. Code both api + ui
3. Code API changes                        3. 1 PR, 1 review
4. Code UI changes                         4. 1 merge, 1 tag
5. PR #1 for api                           5. Done
6. PR #2 for ui
7. Merge api first? ui first?
   -> If ui merges first, build fails
   -> Must coordinate merge order
8. Tag api v0.1.8
9. Tag ui v0.1.8
10. Hope versions stay in sync
```

**This has already happened in practice:** A previous session had to merge `feat/merge-metadata-into-properties` in API first, then fix UI, commit separately, tag separately. Syncing was forgotten multiple times.

#### P2: Root repo has no remote

`openctemio/` root has `.git/` but is **not pushed to GitHub**. docker-compose.yml, go.work, docs/ are all untracked on remote. If cloned from scratch, manual setup is required.

#### P3: Release versioning is fragmented

Each release requires:
- Tag api repo (v0.1.8)
- Tag ui repo (v0.1.8)
- Tag agent repo (if changed)
- Update helm-charts
- Verify version compatibility

With monorepo: 1 tag = 1 release = everything stays in sync.

#### P4: CI/CD duplication

- `api/.github/workflows/ci.yml` — Go lint, test, build
- `ui/.github/workflows/ci.yml` — Node lint, type-check, build
- `agent/.github/workflows/ci.yml` — Go lint, test
- No cross-project CI (e.g., test API+UI integration)

#### P5: Developer onboarding is complex

```bash
# Current: clone 5-7 repos + setup go.work
git clone openctemio/api
git clone openctemio/ui
git clone openctemio/agent
git clone openctemio/sdk-go
git clone openctemio/ctis
# copy docker-compose.yml from somewhere
# setup go.work manually
# hope branches are in sync

# Monorepo: 1 clone
git clone openctemio/openctemio
docker compose up
```

#### P6: Code review is fragmented

Reviewers must open 2-3 PRs to review 1 feature. Context switching between Go and TypeScript PRs. Cannot see the full picture in 1 diff.

### 1.3 Quantitative Data

| Metric | api | ui | agent | Total |
|--------|-----|----|-------|-------|
| Commits | 360 | 354 | 39 | 753 |
| .git size | 34MB | 17MB | 2.3MB | 53.3MB |
| Source size (excl node_modules, vendor) | ~20MB | ~15MB | ~1MB | ~36MB |
| Active branches | 7 | 3 | 1 | 11 |
| CI workflows | 4 | 4 | 2 | 10 |
| Cross-repo features (last 2 months) | — | — | — | ~8 |

---

## 2. Objectives

### Must have
- [ ] Merge api, ui, agent into 1 git repo with **full commit history**
- [ ] 1 tag = 1 release for the entire system
- [ ] docker-compose.yml, go.work, docs/ tracked in the same repo
- [ ] CI path-filtered: changes in api/ only trigger API CI
- [ ] Developer clones 1 repo, `docker compose up` and it runs
- [ ] Do not break Go module paths that are already published
- [ ] Do not break existing Docker images

### Nice to have
- [ ] Unified Makefile (`make api-test`, `make ui-lint`, `make all`)
- [ ] Cross-project CI (API changes trigger E2E test)
- [ ] Shared .github/ templates (issue, PR)
- [ ] Git hooks for format/lint per directory

### Non-goals
- Merge sdk-go or ctis (published modules, external consumers)
- Change Go module paths (keep `github.com/openctemio/api`)
- Rewrite CI from scratch (adapt existing workflows)

---

## 3. Decision Analysis: What to Merge, What to Keep

### 3.1 Decision matrix

| Repo | Coupling | Consumers | Publish cycle | Decision | Reason |
|------|----------|-----------|---------------|----------|--------|
| **api** | Core, everything depends on it | Internal only | Every release | **MERGE** | Core app, always deployed together with ui |
| **ui** | Depends on API endpoints | Internal only | Every release | **MERGE** | Core app, always deployed together with api |
| **agent** | Uses sdk-go, pushes data to api | Internal only | Every release | **MERGE** | Tightly coupled, frequently changes together with api |
| **sdk-go** | Published module | External users | Semantic versioning | **KEEP SEPARATE** | Public interface, consumers `go get` it |
| **ctis** | Published module | api, sdk-go, agent | Semantic versioning | **KEEP SEPARATE** | Shared contract, zero-dep policy |
| **schemas** | Deprecated | Moved to ctis | N/A | **ARCHIVE** | Already migrated into ctis |
| **helm-charts** | Deployment config | Ops team | Per release | **MERGE** | Deployed with same version, always needs syncing |

### 3.2 Why should agent be merged?

1. Agent changes every time the API ingest format changes
2. Agent uses sdk-go, but sdk-go references ctis types = same data contract
3. 39 commits, 2.9MB — near-zero overhead
4. Recon parsers in agent must match normalization rules in api
5. Docker compose already orchestrates all 3

### 3.3 Why should sdk-go + ctis stay separate?

1. **Published Go modules**: Users run `go get github.com/openctemio/sdk-go` — path must stay stable
2. **Independent versioning**: sdk-go v0.3.0 does not require api to also release
3. **Zero external dependencies** (ctis): Merging into monorepo would pull in Go workspace deps
4. **Different release cadence**: API releases weekly, sdk-go releases monthly

---

## 4. Target Monorepo Structure

```
openctemio/                           <- github.com/openctemio/openctemio
├── .github/
│   ├── workflows/
│   │   ├── api-ci.yml               <- Go: lint, test, build (path: api/**)
│   │   ├── api-docker.yml           <- Build + push API image (path: api/**)
│   │   ├── ui-ci.yml                <- Node: lint, type-check, build (path: ui/**)
│   │   ├── ui-docker.yml            <- Build + push UI image (path: ui/**)
│   │   ├── agent-ci.yml             <- Go: lint, test (path: agent/**)
│   │   ├── agent-docker.yml         <- Build + push Agent image (path: agent/**)
│   │   ├── release.yml              <- Tag-triggered: build all, create GitHub release
│   │   └── security.yml             <- CodeQL, govulncheck, Trivy (all paths)
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
│
├── api/                              <- Go backend
│   ├── cmd/
│   ├── internal/
│   ├── pkg/
│   ├── migrations/
│   ├── tests/
│   ├── scripts/
│   ├── docs/                         <- API-specific docs (architecture, rfcs)
│   ├── Dockerfile
│   ├── go.mod                        <- module github.com/openctemio/api (UNCHANGED)
│   ├── go.sum
│   ├── Makefile                      <- API-specific targets
│   └── CLAUDE.md
│
├── ui/                               <- Next.js frontend
│   ├── src/
│   ├── public/
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   ├── next.config.ts
│   └── CLAUDE.md
│
├── agent/                            <- Go agent
│   ├── cmd/
│   ├── internal/
│   ├── Dockerfile
│   ├── go.mod                        <- module github.com/openctemio/agent (UNCHANGED)
│   └── go.sum
│
├── deploy/
│   └── helm/                         <- Helm charts (merged from helm-charts repo)
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│
├── docs/                             <- Project-wide docs (GitHub Pages, setup guides)
│   ├── architecture/
│   ├── development/
│   │   ├── getting-started.md
│   │   └── local-setup.md
│   └── rfcs/                         <- Can be moved from api/docs/rfcs/ to here
│
├── docker-compose.yml                <- Development orchestration
├── docker-compose.prod.yml           <- Production overrides
├── docker-compose.monitoring.yml     <- Monitoring stack
├── go.work                           <- use ./api ./agent
├── go.work.sum
├── Makefile                          <- Root: unified targets
├── .env.example
├── .gitignore
├── CLAUDE.md                         <- Root-level AI guidelines
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md
└── SECURITY.md
```

### 4.1 Changes Compared to Current State

| Item | Before | After |
|------|--------|-------|
| Git repos | 3 (api, ui, agent) + root untracked | 1 (openctemio) |
| docker-compose.yml | Root (untracked) | Root (tracked) |
| go.work | Root (untracked) | Root (tracked) |
| helm-charts | Separate repo | `deploy/helm/` |
| docs (global) | Untracked directory | `docs/` |
| CI workflows | 3 repos x 4 files = 12 | 1 repo x 8 files = 8 |
| Release tag | 3 tags (api, ui, agent) | 1 tag |
| README/LICENSE/etc | Duplicated across repos | 1 copy at root |

### 4.2 File migration map

```
FROM                                    -> TO
─────────────────────────────────────   ──────────────────────────────────
api/.github/workflows/ci.yml           -> .github/workflows/api-ci.yml
api/.github/workflows/release.yml      -> .github/workflows/release.yml (merge)
api/.github/workflows/security.yml     -> .github/workflows/security.yml (merge)
api/.github/workflows/docker-publish.yml -> .github/workflows/api-docker.yml

ui/.github/workflows/ci.yml            -> .github/workflows/ui-ci.yml
ui/.github/workflows/release.yml       -> .github/workflows/release.yml (merge)
ui/.github/workflows/security.yml      -> .github/workflows/security.yml (merge)
ui/.github/workflows/docker-publish.yml -> .github/workflows/ui-docker.yml

agent/.github/workflows/*              -> .github/workflows/agent-*.yml

helm-charts/                           -> deploy/helm/

root docker-compose.yml                -> docker-compose.yml (stays)
root go.work                           -> go.work (stays)
root docs/                             -> docs/ (stays)

api/docs/rfcs/                         -> docs/rfcs/ (project-wide, not api-specific)
api/docs/architecture/                 -> stays at api/docs/ (api-specific)
```

---

## 5. Detailed Implementation Plan

### Precondition: Release v0.1.8 before starting

Merge develop into main and tag v0.1.8 for api + ui + agent. This is the **final multi-repo release**. If a hotfix is needed for v0.1.8, it can still be done on the old repo (archived, not deleted).

### Phase 1: Prepare monorepo (on local machine)

```bash
# ============================================================
# Step 1.1: Create a completely clean new repo
# ============================================================
mkdir /tmp/openctemio-monorepo && cd /tmp/openctemio-monorepo
git init
git commit --allow-empty -m "chore: initialize monorepo"

# ============================================================
# Step 1.2: Merge API history using git subtree
# ============================================================
# git subtree add preserves ALL commit history, rewrites paths
# with the api/ prefix

git remote add api-origin git@github.com:openctemio/api.git
git fetch api-origin

# Merge main branch (v0.1.8 tagged)
git subtree add --prefix=api api-origin/main --squash=false

# Verify: git log --oneline -- api/ | wc -l  -> ~360 commits
# Verify: git log --follow api/cmd/main.go   -> full history

# ============================================================
# Step 1.3: Merge UI history
# ============================================================
git remote add ui-origin git@github.com:openctemio/ui.git
git fetch ui-origin
git subtree add --prefix=ui ui-origin/main --squash=false

# ============================================================
# Step 1.4: Merge Agent history
# ============================================================
git remote add agent-origin git@github.com:openctemio/agent.git
git fetch agent-origin
git subtree add --prefix=agent agent-origin/main --squash=false

# ============================================================
# Step 1.5: Merge Helm Charts history
# ============================================================
git remote add helm-origin https://github.com/openctemio/helm-charts.git
git fetch helm-origin
git subtree add --prefix=deploy/helm helm-origin/main --squash=false
```

**Why `git subtree add` instead of `git subtree add --squash`?**

| Method | History | Blame | Bisect | Merge conflicts |
|--------|---------|-------|--------|-----------------|
| `subtree add` (no squash) | Full history preserved | `git blame` works | `git bisect` works | Possible if root has files with same paths |
| `subtree add --squash` | 1 squash commit | Loses blame | Loses bisect | No conflicts |
| Copy files (no history) | None | None | None | None |

**Recommendation: `--squash=false`** (default). History of 753 commits (~53MB .git) is entirely acceptable.

### Phase 2: Copy root-level files

```bash
# ============================================================
# Step 2.1: Copy files from the current root repo
# ============================================================

# Docker Compose files
cp /path/to/current/openctemio/docker-compose.yml .
cp /path/to/current/openctemio/docker-compose.monitoring.yml .
cp /path/to/current/openctemio/docker-compose.prod.yml .  # if exists

# Go workspace
cp /path/to/current/openctemio/go.work .
cp /path/to/current/openctemio/go.work.sum .

# Docs
cp -r /path/to/current/openctemio/docs/ docs/

# Root files
cp /path/to/current/openctemio/README.md .
cp /path/to/current/openctemio/LICENSE .
cp /path/to/current/openctemio/CHANGELOG.md .
cp /path/to/current/openctemio/CONTRIBUTING.md .
cp /path/to/current/openctemio/CODE_OF_CONDUCT.md .
cp /path/to/current/openctemio/SECURITY.md .
cp /path/to/current/openctemio/.env.example .  # if exists

# ============================================================
# Step 2.2: Update go.work
# ============================================================
cat > go.work << 'EOF'
go 1.26

use (
    ./api
    ./agent
)
EOF
# Note: sdk-go is no longer local -> remove from go.work
# Agent and API reference sdk-go/ctis via go.mod (remote module)

# ============================================================
# Step 2.3: Create root .gitignore
# ============================================================
cat > .gitignore << 'EOF'
# Build outputs
server
/tmp/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Environment
.env
.env.local
.env.*.local

# Go
go.work.sum

# Node (ui-specific ones are in ui/.gitignore)
node_modules/
EOF

# ============================================================
# Step 2.4: Commit root files
# ============================================================
git add .
git commit -m "chore: add root config files (docker-compose, go.work, docs)"
```

### Phase 3: Update CI/CD workflows

```bash
# ============================================================
# Step 3.1: Remove per-repo .github/ directories
# ============================================================
# Old workflows in api/.github/, ui/.github/, agent/.github/
# will NOT work in monorepo (GitHub only reads .github/ at root)

# Delete but keep for reference
mkdir -p .github/workflows/archive/
cp api/.github/workflows/*.yml .github/workflows/archive/api-
cp ui/.github/workflows/*.yml .github/workflows/archive/ui-

rm -rf api/.github/
rm -rf ui/.github/
rm -rf agent/.github/

# ============================================================
# Step 3.2: Create new workflows (details in Section 6)
# ============================================================
# Create 8 new workflow files in .github/workflows/

git add .github/
git commit -m "ci: migrate to monorepo workflows with path filtering"
```

### Phase 4: Update Dockerfiles and docker-compose

```bash
# ============================================================
# Step 4.1: Update docker-compose.yml
# ============================================================
# Build context DOES NOT change since it is already ./api and ./ui
# Volumes DO NOT change
# ONLY need to remove sdk-go volume mount (if sdk-go is no longer local)
```

**docker-compose.yml changes:**

```yaml
# BEFORE (api volumes)
volumes:
  - ./api:/app
  - ./sdk-go:/app/sdk-go        # <- REMOVE this line

# AFTER
volumes:
  - ./api:/app
```

Note: If sdk-go still needs to be developed locally, keep sdk-go outside the monorepo and mount via `go.work` replace directive.

### Phase 5: Create root Makefile

```makefile
# ============================================================
# Root Makefile — OpenCTEM Monorepo
# ============================================================
.PHONY: help dev up down api-test ui-test agent-test test lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Development ---
dev: ## Start all services (dev mode)
	docker compose up

up: ## Start all services (detached)
	docker compose up -d

down: ## Stop all services
	docker compose down

logs: ## Tail all logs
	docker compose logs -f

# --- API ---
api-test: ## Run API tests
	cd api && make test

api-lint: ## Lint API code
	cd api && GOWORK=off golangci-lint run ./...

api-fmt: ## Format API code
	cd api && goimports -w .

api-migrate: ## Run database migrations
	cd api && make migrate-up

# --- UI ---
ui-test: ## Run UI tests
	cd ui && npm test

ui-lint: ## Lint UI code
	cd ui && npm run lint

ui-build: ## Build UI
	cd ui && npm run build

ui-type-check: ## TypeScript type check
	cd ui && npm run type-check

# --- Agent ---
agent-test: ## Run Agent tests
	cd agent && go test ./...

agent-lint: ## Lint Agent code
	cd agent && GOWORK=off golangci-lint run ./...

# --- All ---
test: api-test ui-test agent-test ## Run all tests

lint: api-lint ui-lint agent-lint ## Lint everything

# --- Release ---
tag: ## Create release tag (usage: make tag v=0.2.0)
	@test -n "$(v)" || (echo "Usage: make tag v=0.2.0" && exit 1)
	git tag -a v$(v) -m "Release v$(v)"
	@echo "Tagged v$(v). Run 'git push origin v$(v)' to release."
```

### Phase 6: Push and archive

```bash
# ============================================================
# Step 6.1: Create new GitHub repo
# ============================================================
gh repo create openctemio/openctemio --public \
  --description "OpenCTEM — Continuous Threat Exposure Management Platform"

# ============================================================
# Step 6.2: Push monorepo
# ============================================================
git remote add origin git@github.com:openctemio/openctemio.git
git push -u origin main

# ============================================================
# Step 6.3: Tag initial monorepo release
# ============================================================
git tag -a v0.2.0 -m "Release v0.2.0 — First monorepo release"
git push origin v0.2.0

# ============================================================
# Step 6.4: Archive old repos
# ============================================================
# DO NOT delete — archive to preserve link references, issues, stars
gh repo archive openctemio/api --yes
gh repo archive openctemio/ui --yes
gh repo archive openctemio/agent --yes
gh repo archive openctemio/helm-charts --yes

# Update each repo description to redirect
gh repo edit openctemio/api --description "ARCHIVED — Moved to github.com/openctemio/openctemio/api"
gh repo edit openctemio/ui --description "ARCHIVED — Moved to github.com/openctemio/openctemio/ui"
gh repo edit openctemio/agent --description "ARCHIVED — Moved to github.com/openctemio/openctemio/agent"
```

---

## 6. CI/CD Design

### 6.1 Path filtering strategy

GitHub Actions `paths` filter allows triggering a workflow only when files at a specific path change.

```yaml
# .github/workflows/api-ci.yml
name: API CI
on:
  push:
    branches: [main, develop]
    paths:
      - 'api/**'
      - 'go.work'
      - '.github/workflows/api-ci.yml'
  pull_request:
    branches: [main, develop]
    paths:
      - 'api/**'
      - 'go.work'
      - '.github/workflows/api-ci.yml'
```

### 6.2 Workflow matrix

| Workflow | Trigger paths | Jobs | Estimated time |
|----------|---------------|------|----------------|
| `api-ci.yml` | `api/**`, `go.work` | lint, test (postgres+redis), build | ~3 min |
| `ui-ci.yml` | `ui/**` | lint, type-check, build | ~2 min |
| `agent-ci.yml` | `agent/**`, `go.work` | lint, test, build | ~1 min |
| `api-docker.yml` | `api/**` (main only) | Build + push ghcr.io/openctemio/api | ~5 min |
| `ui-docker.yml` | `ui/**` (main only) | Build + push ghcr.io/openctemio/ui | ~5 min |
| `agent-docker.yml` | `agent/**` (main only) | Build + push ghcr.io/openctemio/agent | ~3 min |
| `release.yml` | Tag `v*` | Build all images, create GitHub release | ~10 min |
| `security.yml` | Weekly + push main | CodeQL (Go+JS), govulncheck, Trivy | ~8 min |

### 6.3 API CI workflow details

```yaml
# .github/workflows/api-ci.yml
name: API CI

on:
  push:
    branches: [main, develop]
    paths:
      - 'api/**'
      - 'go.work'
      - '.github/workflows/api-ci.yml'
  pull_request:
    branches: [main, develop]
    paths:
      - 'api/**'
      - 'go.work'
      - '.github/workflows/api-ci.yml'

env:
  GO_VERSION: "1.26"

defaults:
  run:
    working-directory: api

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: api/go.sum
      - run: go vet ./...
      - run: go install honnef.co/go/tools/cmd/staticcheck@latest
      - run: staticcheck ./...

  test:
    name: Test
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17-alpine
        env:
          POSTGRES_USER: openctem
          POSTGRES_PASSWORD: secret
          POSTGRES_DB: app_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7-alpine
        ports: ["6379:6379"]
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: api/go.sum
      - run: go test -race -coverprofile=coverage.out ./...
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USER: openctem
          DB_PASSWORD: secret
          DB_NAME: app_test
          REDIS_ADDR: localhost:6379
      - uses: actions/upload-artifact@v4
        with:
          name: api-coverage
          path: api/coverage.out

  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: ${{ env.GO_VERSION }}
          cache-dependency-path: api/go.sum
      - run: go build -o /dev/null ./cmd/...
```

### 6.4 UI CI workflow details

```yaml
# .github/workflows/ui-ci.yml
name: UI CI

on:
  push:
    branches: [main, develop]
    paths:
      - 'ui/**'
      - '.github/workflows/ui-ci.yml'
  pull_request:
    branches: [main, develop]
    paths:
      - 'ui/**'
      - '.github/workflows/ui-ci.yml'

env:
  NODE_VERSION: "20"

defaults:
  run:
    working-directory: ui

jobs:
  quality:
    name: Quality Checks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
          cache-dependency-path: ui/package-lock.json
      - run: npm ci
      - run: npm run type-check
      - run: npm run lint
      - run: npm run format:check

  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
          cache-dependency-path: ui/package-lock.json
      - run: npm ci
      - run: npm run build
        env:
          NEXT_PUBLIC_API_URL: http://localhost:8080
```

### 6.5 Release workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ['v*']

env:
  REGISTRY: ghcr.io
  GO_VERSION: "1.26"
  NODE_VERSION: "20"

jobs:
  release-api:
    name: Build & Push API Image
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v6
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: ./api
          push: true
          tags: |
            ${{ env.REGISTRY }}/openctemio/api:${{ github.ref_name }}
            ${{ env.REGISTRY }}/openctemio/api:latest

  release-ui:
    name: Build & Push UI Image
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v6
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: ./ui
          push: true
          tags: |
            ${{ env.REGISTRY }}/openctemio/ui:${{ github.ref_name }}
            ${{ env.REGISTRY }}/openctemio/ui:latest

  release-agent:
    name: Build & Push Agent Image
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v6
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: ./agent
          push: true
          tags: |
            ${{ env.REGISTRY }}/openctemio/agent:${{ github.ref_name }}
            ${{ env.REGISTRY }}/openctemio/agent:latest

  create-release:
    name: Create GitHub Release
    needs: [release-api, release-ui, release-agent]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: Generate changelog
        id: changelog
        run: |
          PREV_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")
          if [ -n "$PREV_TAG" ]; then
            echo "changelog<<EOF" >> $GITHUB_OUTPUT
            git log ${PREV_TAG}..HEAD --pretty=format:"- %s" >> $GITHUB_OUTPUT
            echo "EOF" >> $GITHUB_OUTPUT
          fi
      - uses: softprops/action-gh-release@v2
        with:
          body: |
            ## What's Changed
            ${{ steps.changelog.outputs.changelog }}

            ## Docker Images
            - `ghcr.io/openctemio/api:${{ github.ref_name }}`
            - `ghcr.io/openctemio/ui:${{ github.ref_name }}`
            - `ghcr.io/openctemio/agent:${{ github.ref_name }}`
```

### 6.6 Branching strategy

```
main ─────────────────────────────────── production
  │
  └── develop ──────────────────────────── staging/integration
        │
        ├── feat/asset-normalization ──── feature branch (touches api/ + ui/)
        ├── fix/login-bug ─────────────── bugfix (touches ui/ only)
        └── feat/new-scanner ──────────── feature (touches agent/ only)
```

**No change** from current practice — all 3 repos already use `main` + `develop` + feature branches.

---

## 7. Docker & Development workflow

### 7.1 docker-compose.yml — Minimal changes

```yaml
# Only remove sdk-go volume mount if not developing locally
services:
  api:
    build:
      context: ./api          # <- UNCHANGED
      dockerfile: Dockerfile
      target: development
    volumes:
      - ./api:/app            # <- UNCHANGED
      # - ./sdk-go:/app/sdk-go  <- REMOVED (sdk-go no longer local)

  ui:
    build:
      context: ./ui           # <- UNCHANGED
      dockerfile: Dockerfile
      target: development
    volumes:
      - ./ui:/app             # <- UNCHANGED
```

### 7.2 Dockerfiles — UNCHANGED

Dockerfiles in `api/Dockerfile` and `ui/Dockerfile` reference paths relative to build context (`./api` or `./ui`). The monorepo does not affect them.

### 7.3 New developer workflow

```bash
# Clone
git clone git@github.com:openctemio/openctemio.git
cd openctemio

# Start
docker compose up

# Develop feature touching both API + UI
git checkout -b feat/my-feature
# Edit api/... and ui/...
# API auto-reloads (air), UI auto-reloads (next dev)

# Test
make api-test
make ui-lint

# Commit — 1 atomic commit for both API + UI changes
git add api/internal/app/my_service.go ui/src/features/my-feature/
git commit -m "feat: add my-feature (API + UI)"

# PR
gh pr create --title "feat: add my-feature"
# -> CI runs api-ci.yml AND ui-ci.yml (both paths changed)
```

### 7.4 SDK-Go local development (when needed)

If sdk-go needs to be developed simultaneously with api/agent:

```bash
# Clone sdk-go alongside the monorepo
git clone git@github.com:openctemio/sdk-go.git ../sdk-go

# Temporarily update go.work
# go.work:
# use (
#     ./api
#     ./agent
#     ../sdk-go    <- add temporarily
# )

# Or use replace directive in api/go.mod (remember to remove before committing)
```

---

## 8. Go module strategy

### 8.1 Keep module paths unchanged

```
api/go.mod    -> module github.com/openctemio/api     (UNCHANGED)
agent/go.mod  -> module github.com/openctemio/agent   (UNCHANGED)
```

**Why not change to `github.com/openctemio/openctemio/api`?**

1. **Breaking change**: All import paths in code would need to change
2. **Go proxy cache**: Old module still cached, causing confusion
3. **sdk-go dependency**: sdk-go/agent `require github.com/openctemio/api` -> would need to update sdk-go
4. **Not necessary**: Go workspace (`go.work`) handles path mapping; module path does not need to match repo path

### 8.2 go.work in the monorepo

```go
// go.work
go 1.26

use (
    ./api
    ./agent
)
```

- `go.work` allows `api` and `agent` to reference each other locally
- sdk-go and ctis are still resolved from Go proxy (remote modules)
- `go.work.sum` should be in `.gitignore` (generated file)

### 8.3 Future: If module paths need to change

If the decision is made later to change paths:

```bash
# 1. Update go.mod
cd api && go mod edit -module github.com/openctemio/openctemio/api

# 2. Update all imports
find api/ -name '*.go' -exec sed -i \
  's|github.com/openctemio/api/|github.com/openctemio/openctemio/api/|g' {} +

# 3. Test
cd api && go build ./...
```

**Recommendation: Do not change at v0.2.0. Change at v1.0.0 if needed (breaking change is appropriate for a major version).**

---

## 9. Risks and Mitigations

### R1: Git history merge conflicts

**Risk**: `git subtree add` may conflict if the root repo already has files at the same paths.

**Mitigation**: Start from a new repo (empty). Do not use the current root repo (which has untracked files and messy history).

**Probability**: Low (new repo, empty initial commit).

### R2: CI runs when it should not

**Risk**: Changing README.md at root triggers all workflows.

**Mitigation**: Path filters only trigger when files in `api/**`, `ui/**`, or `agent/**` change. Root files (README, LICENSE) do not trigger any CI.

**Edge case**: `go.work` change triggers both api-ci + agent-ci. This is correct behavior since a workspace change can affect both.

### R3: Repo size too large

**Risk**: Repo size increases, slowing clone times.

| Component | Size |
|-----------|------|
| api .git | 34MB |
| ui .git | 17MB |
| agent .git | 2.3MB |
| **Total .git** | **~53MB** |
| Source code (excl deps) | ~36MB |
| **Total clone size** | **~90MB** |

**Mitigation**: 90MB is entirely normal. The Kubernetes monorepo is 1.5GB+. If needed, use `git clone --depth=1` for CI.

### R4: Branch sync from old repos

**Risk**: Feature branches on old repos (api/feat/decouple-sdk) are lost.

**Mitigation**:
1. Merge all important branches into develop **before** migrating
2. Or migrate the branch using `git subtree`:
   ```bash
   git fetch api-origin feat/decouple-sdk
   git checkout -b feat/decouple-sdk
   git subtree add --prefix=api api-origin/feat/decouple-sdk
   ```

**Recommendation**: Merge `feat/decouple-sdk` into develop first. This is the only important branch.

### R5: GitHub Issues/PRs on old repos

**Risk**: Links to issues/PRs on openctemio/api#123 will still work (archived, not deleted).

**Mitigation**: Archive old repos — issues/PRs become read-only but URLs continue to work. New issues are created on openctemio/openctemio.

### R6: Docker image names change

**Risk**: Production is currently pulling `ghcr.io/openctemio/api:v0.1.8`.

**Mitigation**: Docker image names **DO NOT change**. CI builds from `./api` context, pushes to the same registry + image name. Monorepo = source code organization, does not affect artifact names.

### R7: Dependabot/Renovate

**Risk**: Dependabot needs separate config for Go + Node in the same repo.

**Mitigation**:
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/api"
    schedule:
      interval: "weekly"
  - package-ecosystem: "gomod"
    directory: "/agent"
    schedule:
      interval: "weekly"
  - package-ecosystem: "npm"
    directory: "/ui"
    schedule:
      interval: "weekly"
```

---

## 10. Rollback plan

If the monorepo causes unforeseen problems:

```bash
# Old repos are still archived on GitHub
# Unarchive:
gh repo unarchive openctemio/api
gh repo unarchive openctemio/ui
gh repo unarchive openctemio/agent

# Developers switch back to multi-repo workflow
# CI on old repos is still configured
```

**Time to rollback**: < 5 minutes (unarchive repos).

**Data loss**: None — monorepo preserves history, old repos remain intact.

---

## 11. Implementation Checklist

### Pre-migration

- [ ] Merge all pending feature branches (especially `feat/decouple-sdk`)
- [ ] Tag v0.1.8 for api, ui, agent (final multi-repo release)
- [ ] Verify all CI is green on main
- [ ] Backup: clone all repos locally (including all branches)
- [ ] Create GitHub repo: `openctemio/openctemio`

### Migration

- [ ] `git init` new repo
- [ ] `git subtree add --prefix=api` from api/main
- [ ] `git subtree add --prefix=ui` from ui/main
- [ ] `git subtree add --prefix=agent` from agent/main
- [ ] `git subtree add --prefix=deploy/helm` from helm-charts/main
- [ ] Copy root files (docker-compose, go.work, docs, README, etc.)
- [ ] Create `.github/workflows/` (8 files)
- [ ] Create root Makefile
- [ ] Create root `.gitignore`
- [ ] Create root `CLAUDE.md`
- [ ] Create `.github/dependabot.yml`
- [ ] Update `docker-compose.yml` (remove sdk-go volume)
- [ ] Update `go.work` (only ./api, ./agent)

### Verification

- [ ] `git log --follow api/cmd/main.go` — verify full history
- [ ] `git log --follow ui/src/app/layout.tsx` — verify full history
- [ ] `docker compose up` — all services start
- [ ] `make api-test` — API tests pass
- [ ] `make ui-lint` — UI lint passes
- [ ] `go build ./api/cmd/...` — API builds
- [ ] API curl health check: `curl http://localhost:8080/health`
- [ ] UI loads: `http://localhost:3000`

### Post-migration

- [ ] Push monorepo to GitHub
- [ ] Tag v0.2.0 (first monorepo release)
- [ ] Archive old repos (api, ui, agent, helm-charts)
- [ ] Update old repo descriptions with redirect message
- [ ] Update docs/README with new repo URL
- [ ] Update CI secrets on new repo (if needed)
- [ ] Update deploy scripts/helm values with new image references (if changed)
- [ ] Notify the team (if applicable)

---

## 12. Open Questions

### Q1: Where should RFCs live?

**Option A**: Keep at `api/docs/rfcs/` (current) — api-specific
**Option B**: Move to `docs/rfcs/` (root) — project-wide

**Recommendation**: Option B — RFCs are project-wide decisions, not API-only.

### Q2: CLAUDE.md strategy

**Option A**: 1 file at root
**Option B**: Root CLAUDE.md (shared) + api/CLAUDE.md (Go rules) + ui/CLAUDE.md (TS rules)

**Recommendation**: Option B — Keep per-project CLAUDE.md files, add a root file for shared rules.

### Q3: Versioning scheme after monorepo

**Option A**: Single version for the entire project (v0.2.0, v0.3.0...)
**Option B**: Per-component tags (api/v0.2.0, ui/v0.2.0)

**Recommendation**: Option A — Monorepo = single version. If you need to know which component changed, check the changelog.

### Q4: develop branch or trunk-based?

**Current**: `main` + `develop` + feature branches (Gitflow-lite)
**Alternative**: Trunk-based (main only + feature branches)

**Recommendation**: Keep Gitflow-lite for v0.2.x. Evaluate trunk-based when the team grows.

### Q5: Do we need lerna/nx/turborepo?

**No.** These tools solve problems of JavaScript monorepos with many packages. OpenCTEM has:
- Go modules (built-in workspace support via `go.work`)
- 1 Next.js app (not a multi-package JS project)
- Makefile is sufficient for orchestration

Adding tooling = adding unnecessary complexity.

---

## References

- [GitHub: About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) — CODEOWNERS for path-based review assignment
- [GitHub Actions: paths filter](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onpushpull_requestpull_request_targetpathspaths-ignore)
- [git subtree tutorial](https://www.atlassian.com/git/tutorials/git-subtree)
- [Monorepo vs Multi-repo](https://github.com/joelparkerhenderson/monorepo-vs-polyrepo) — comprehensive analysis
