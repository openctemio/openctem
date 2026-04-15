# RFC-003: Monorepo Consolidation — Gộp api + ui + agent vào một repository

- **Status**: Draft
- **Created**: 2026-04-15
- **Author**: OpenCTEM Team
- **Priority**: High
- **Estimated effort**: 1-2 ngày (migration), 1 ngày (CI/CD), 1 ngày (verification)

---

## Mục lục

1. [Hiện trạng và vấn đề](#1-hiện-trạng-và-vấn-đề)
2. [Mục tiêu](#2-mục-tiêu)
3. [Phân tích quyết định: Gộp gì, giữ gì](#3-phân-tích-quyết-định-gộp-gì-giữ-gì)
4. [Cấu trúc monorepo mục tiêu](#4-cấu-trúc-monorepo-mục-tiêu)
5. [Kế hoạch thực hiện chi tiết](#5-kế-hoạch-thực-hiện-chi-tiết)
6. [CI/CD thiết kế](#6-cicd-thiết-kế)
7. [Docker & Development workflow](#7-docker--development-workflow)
8. [Go module strategy](#8-go-module-strategy)
9. [Rủi ro và giải pháp](#9-rủi-ro-và-giải-pháp)
10. [Rollback plan](#10-rollback-plan)
11. [Checklist thực hiện](#11-checklist-thực-hiện)
12. [Câu hỏi mở](#12-câu-hỏi-mở)

---

## 1. Hiện trạng và vấn đề

### 1.1 Cấu trúc hiện tại

```
openctemio/                    ← git repo (local only, KHÔNG có remote)
├── .git/                      ← 10+ commits, từng track submodules
├── docker-compose.yml         ← orchestrates api + ui
├── go.work                    ← links api, agent, sdk-go
├── helm-charts/               ← separate git repo
├── docs/                      ← GitHub Pages (not tracked by any repo)
│
├── api/                       ← github.com/openctemio/api     (360 commits, 343MB)
│   └── .git/                  ← 34MB git history
├── ui/                        ← github.com/openctemio/ui      (354 commits, 1.6GB*)
│   └── .git/                  ← 17MB git history
├── agent/                     ← github.com/openctemio/agent   (39 commits, 2.9MB)
│   └── .git/                  ← 2.3MB git history
│
├── sdk-go/                    ← github.com/openctemio/sdk-go  (39 commits, published module)
├── ctis/                      ← github.com/openctemio/ctis    (2 commits, published module)
└── schemas/                   ← github.com/rediverio/schemas  (14 commits, deprecated)
```

*\* ui 1.6GB chủ yếu là node_modules (gitignored). Thực tế source + .git ≈ 50MB.*

### 1.2 Vấn đề cụ thể

#### P1: Atomic changes bất khả thi

Khi một feature cần thay đổi cả API + UI (ví dụ: xóa `metadata` column, thêm sub_type, asset normalization):

```
Hiện tại (multi-repo):                    Mong muốn (monorepo):
─────────────────────────                  ──────────────────────
1. Branch api/feat/xyz                     1. Branch feat/xyz
2. Branch ui/feat/xyz                      2. Code cả api + ui
3. Code API changes                        3. 1 PR, 1 review
4. Code UI changes                         4. 1 merge, 1 tag
5. PR #1 cho api                           5. Done
6. PR #2 cho ui
7. Merge api trước? ui trước?
   → Nếu merge ui trước, build fail
   → Phải coordinate merge order
8. Tag api v0.1.8
9. Tag ui v0.1.8
10. Cầu nguyện version khớp nhau
```

**Thực tế đã xảy ra:** Session trước phải merge `feat/merge-metadata-into-properties` ở API trước, rồi mới sửa UI, commit riêng, tag riêng. Nhiều lần quên sync.

#### P2: Root repo không có remote

`openctemio/` root có `.git/` nhưng **không push lên GitHub**. docker-compose.yml, go.work, docs/ đều untracked trên remote. Nếu clone lại từ đầu, phải setup thủ công.

#### P3: Release versioning phân mảnh

Mỗi release phải:
- Tag api repo (v0.1.8)
- Tag ui repo (v0.1.8)
- Tag agent repo (nếu có thay đổi)
- Update helm-charts
- Kiểm tra version compatibility

Với monorepo: 1 tag = 1 release = mọi thứ khớp nhau.

#### P4: CI/CD duplicate

- `api/.github/workflows/ci.yml` — Go lint, test, build
- `ui/.github/workflows/ci.yml` — Node lint, type-check, build
- `agent/.github/workflows/ci.yml` — Go lint, test
- Không có cross-project CI (ví dụ: test API+UI integration)

#### P5: Developer onboarding phức tạp

```bash
# Hiện tại: clone 5-7 repos + setup go.work
git clone openctemio/api
git clone openctemio/ui
git clone openctemio/agent
git clone openctemio/sdk-go
git clone openctemio/ctis
# copy docker-compose.yml từ đâu đó
# setup go.work thủ công
# cầu nguyện branch khớp nhau

# Monorepo: 1 clone
git clone openctemio/openctemio
docker compose up
```

#### P6: Code review fragmented

Reviewer phải mở 2-3 PRs để review 1 feature. Context switching giữa Go và TypeScript PRs. Không thể thấy full picture trong 1 diff.

### 1.3 Dữ liệu định lượng

| Metric | api | ui | agent | Tổng |
|--------|-----|----|-------|------|
| Commits | 360 | 354 | 39 | 753 |
| .git size | 34MB | 17MB | 2.3MB | 53.3MB |
| Source size (excl node_modules, vendor) | ~20MB | ~15MB | ~1MB | ~36MB |
| Active branches | 7 | 3 | 1 | 11 |
| CI workflows | 4 | 4 | 2 | 10 |
| Cross-repo features (last 2 months) | — | — | — | ~8 |

---

## 2. Mục tiêu

### Must have
- [ ] Gộp api, ui, agent vào 1 git repo với **toàn bộ commit history**
- [ ] 1 tag = 1 release cho cả hệ thống
- [ ] docker-compose.yml, go.work, docs/ tracked trong cùng repo
- [ ] CI path-filtered: thay đổi api/ chỉ trigger API CI
- [ ] Developer clone 1 repo, `docker compose up` là chạy
- [ ] Không break Go module paths đang published
- [ ] Không break existing Docker images

### Nice to have
- [ ] Unified Makefile (`make api-test`, `make ui-lint`, `make all`)
- [ ] Cross-project CI (API changes trigger E2E test)
- [ ] Shared .github/ templates (issue, PR)
- [ ] Git hooks cho format/lint per directory

### Non-goals
- Merge sdk-go hoặc ctis (published modules, external consumers)
- Đổi Go module paths (giữ `github.com/openctemio/api`)
- Rewrite CI from scratch (adapt existing workflows)

---

## 3. Phân tích quyết định: Gộp gì, giữ gì

### 3.1 Decision matrix

| Repo | Coupling | Consumers | Publish cycle | Quyết định | Lý do |
|------|----------|-----------|---------------|------------|-------|
| **api** | Core, mọi thứ phụ thuộc | Internal only | Mỗi release | **MERGE** | Core app, luôn deploy cùng ui |
| **ui** | Phụ thuộc API endpoints | Internal only | Mỗi release | **MERGE** | Core app, luôn deploy cùng api |
| **agent** | Dùng sdk-go, push data lên api | Internal only | Mỗi release | **MERGE** | Tightly coupled, thường thay đổi cùng api |
| **sdk-go** | Published module | External users | Semantic versioning | **KEEP SEPARATE** | Public interface, consumers `go get` nó |
| **ctis** | Published module | api, sdk-go, agent | Semantic versioning | **KEEP SEPARATE** | Shared contract, zero-dep policy |
| **schemas** | Deprecated | Moved to ctis | N/A | **ARCHIVE** | Đã migrate vào ctis |
| **helm-charts** | Deployment config | Ops team | Per release | **MERGE** | Deploy cùng version, luôn cần sync |

### 3.2 Tại sao agent nên gộp?

1. Agent thay đổi mỗi khi API thay đổi ingest format
2. Agent dùng sdk-go nhưng sdk-go reference ctis types = cùng data contract
3. 39 commits, 2.9MB — overhead gần bằng 0
4. Recon parsers trong agent phải khớp normalization rules trong api
5. Docker compose đã orchestrate cả 3

### 3.3 Tại sao sdk-go + ctis giữ riêng?

1. **Published Go modules**: Users chạy `go get github.com/openctemio/sdk-go` — path phải stable
2. **Independent versioning**: sdk-go v0.3.0 không cần api cũng release
3. **Zero external dependencies** (ctis): Gộp vào monorepo = kéo thêm Go workspace deps
4. **Different release cadence**: API release weekly, sdk-go release monthly

---

## 4. Cấu trúc monorepo mục tiêu

```
openctemio/                           ← github.com/openctemio/openctemio
├── .github/
│   ├── workflows/
│   │   ├── api-ci.yml               ← Go: lint, test, build (path: api/**)
│   │   ├── api-docker.yml           ← Build + push API image (path: api/**)
│   │   ├── ui-ci.yml                ← Node: lint, type-check, build (path: ui/**)
│   │   ├── ui-docker.yml            ← Build + push UI image (path: ui/**)
│   │   ├── agent-ci.yml             ← Go: lint, test (path: agent/**)
│   │   ├── agent-docker.yml         ← Build + push Agent image (path: agent/**)
│   │   ├── release.yml              ← Tag-triggered: build all, create GitHub release
│   │   └── security.yml             ← CodeQL, govulncheck, Trivy (all paths)
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
│
├── api/                              ← Go backend
│   ├── cmd/
│   ├── internal/
│   ├── pkg/
│   ├── migrations/
│   ├── tests/
│   ├── scripts/
│   ├── docs/                         ← API-specific docs (architecture, rfcs)
│   ├── Dockerfile
│   ├── go.mod                        ← module github.com/openctemio/api (UNCHANGED)
│   ├── go.sum
│   ├── Makefile                      ← API-specific targets
│   └── CLAUDE.md
│
├── ui/                               ← Next.js frontend
│   ├── src/
│   ├── public/
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   ├── next.config.ts
│   └── CLAUDE.md
│
├── agent/                            ← Go agent
│   ├── cmd/
│   ├── internal/
│   ├── Dockerfile
│   ├── go.mod                        ← module github.com/openctemio/agent (UNCHANGED)
│   └── go.sum
│
├── deploy/
│   └── helm/                         ← Helm charts (merged from helm-charts repo)
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│
├── docs/                             ← Project-wide docs (GitHub Pages, setup guides)
│   ├── architecture/
│   ├── development/
│   │   ├── getting-started.md
│   │   └── local-setup.md
│   └── rfcs/                         ← Có thể move từ api/docs/rfcs/ ra đây
│
├── docker-compose.yml                ← Development orchestration
├── docker-compose.prod.yml           ← Production overrides
├── docker-compose.monitoring.yml     ← Monitoring stack
├── go.work                           ← use ./api ./agent
├── go.work.sum
├── Makefile                          ← Root: unified targets
├── .env.example
├── .gitignore
├── CLAUDE.md                         ← Root-level AI guidelines
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md
└── SECURITY.md
```

### 4.1 Thay đổi so với hiện tại

| Mục | Trước | Sau |
|-----|-------|-----|
| Git repos | 3 (api, ui, agent) + root untracked | 1 (openctemio) |
| docker-compose.yml | Root (untracked) | Root (tracked) |
| go.work | Root (untracked) | Root (tracked) |
| helm-charts | Separate repo | `deploy/helm/` |
| docs (global) | Untracked directory | `docs/` |
| CI workflows | 3 repos × 4 files = 12 | 1 repo × 8 files = 8 |
| Release tag | 3 tags (api, ui, agent) | 1 tag |
| README/LICENSE/etc | Duplicated across repos | 1 copy at root |

### 4.2 File migration map

```
FROM                                    → TO
─────────────────────────────────────   ──────────────────────────────────
api/.github/workflows/ci.yml           → .github/workflows/api-ci.yml
api/.github/workflows/release.yml      → .github/workflows/release.yml (merge)
api/.github/workflows/security.yml     → .github/workflows/security.yml (merge)
api/.github/workflows/docker-publish.yml → .github/workflows/api-docker.yml

ui/.github/workflows/ci.yml            → .github/workflows/ui-ci.yml
ui/.github/workflows/release.yml       → .github/workflows/release.yml (merge)
ui/.github/workflows/security.yml      → .github/workflows/security.yml (merge)
ui/.github/workflows/docker-publish.yml → .github/workflows/ui-docker.yml

agent/.github/workflows/*              → .github/workflows/agent-*.yml

helm-charts/                           → deploy/helm/

root docker-compose.yml                → docker-compose.yml (stays)
root go.work                           → go.work (stays)
root docs/                             → docs/ (stays)

api/docs/rfcs/                         → docs/rfcs/ (project-wide, không api-specific)
api/docs/architecture/                 → giữ tại api/docs/ (api-specific)
```

---

## 5. Kế hoạch thực hiện chi tiết

### Precondition: Release v0.1.8 trước khi bắt đầu

Merge develop → main và tag v0.1.8 cho cả api + ui + agent. Đây là **bản release cuối cùng dạng multi-repo**. Nếu cần hotfix v0.1.8, vẫn có thể hotfix trên repo cũ (archived, not deleted).

### Phase 1: Chuẩn bị monorepo (trên máy local)

```bash
# ============================================================
# Step 1.1: Tạo repo mới hoàn toàn sạch
# ============================================================
mkdir /tmp/openctemio-monorepo && cd /tmp/openctemio-monorepo
git init
git commit --allow-empty -m "chore: initialize monorepo"

# ============================================================
# Step 1.2: Merge API history bằng git subtree
# ============================================================
# git subtree add giữ TOÀN BỘ commit history, rewrite paths
# thành prefix api/

git remote add api-origin git@github.com:openctemio/api.git
git fetch api-origin

# Merge main branch (v0.1.8 tagged)
git subtree add --prefix=api api-origin/main --squash=false

# Verify: git log --oneline -- api/ | wc -l  → ~360 commits
# Verify: git log --follow api/cmd/main.go   → full history

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

**Tại sao `git subtree add` mà không phải `git subtree add --squash`?**

| Method | History | Blame | Bisect | Merge conflicts |
|--------|---------|-------|--------|-----------------|
| `subtree add` (no squash) | Full history preserved | `git blame` works | `git bisect` works | Possible nếu root có files cùng path |
| `subtree add --squash` | 1 squash commit | Mất blame | Mất bisect | Không conflict |
| Copy files (no history) | Không có | Không có | Không có | Không |

**Khuyến nghị: `--squash=false`** (default). History của 753 commits (~53MB .git) hoàn toàn chấp nhận được.

### Phase 2: Copy root-level files

```bash
# ============================================================
# Step 2.1: Copy files từ root repo hiện tại
# ============================================================

# Docker Compose files
cp /path/to/current/openctemio/docker-compose.yml .
cp /path/to/current/openctemio/docker-compose.monitoring.yml .
cp /path/to/current/openctemio/docker-compose.prod.yml .  # nếu có

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
cp /path/to/current/openctemio/.env.example .  # nếu có

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
# Lưu ý: sdk-go không còn ở local → remove khỏi go.work
# Agent và API reference sdk-go/ctis qua go.mod (remote module)

# ============================================================
# Step 2.3: Tạo root .gitignore
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

### Phase 3: Cập nhật CI/CD workflows

```bash
# ============================================================
# Step 3.1: Remove per-repo .github/ directories
# ============================================================
# Các workflow cũ trong api/.github/, ui/.github/, agent/.github/
# sẽ KHÔNG hoạt động trong monorepo (GitHub chỉ đọc .github/ ở root)

# Xóa nhưng giữ lại để reference
mkdir -p .github/workflows/archive/
cp api/.github/workflows/*.yml .github/workflows/archive/api-
cp ui/.github/workflows/*.yml .github/workflows/archive/ui-

rm -rf api/.github/
rm -rf ui/.github/
rm -rf agent/.github/

# ============================================================
# Step 3.2: Tạo workflows mới (chi tiết ở Section 6)
# ============================================================
# Tạo 8 workflow files mới trong .github/workflows/

git add .github/
git commit -m "ci: migrate to monorepo workflows with path filtering"
```

### Phase 4: Cập nhật Dockerfiles và docker-compose

```bash
# ============================================================
# Step 4.1: Update docker-compose.yml
# ============================================================
# Build context KHÔNG thay đổi vì đã là ./api và ./ui
# Volumes KHÔNG thay đổi
# CHỈ cần xóa sdk-go volume mount (nếu sdk-go không ở local nữa)
```

**docker-compose.yml changes:**

```yaml
# BEFORE (api volumes)
volumes:
  - ./api:/app
  - ./sdk-go:/app/sdk-go        # ← XÓA dòng này

# AFTER
volumes:
  - ./api:/app
```

Lưu ý: Nếu vẫn cần develop sdk-go locally, giữ sdk-go ở ngoài monorepo và mount qua `go.work` replace directive.

### Phase 5: Tạo root Makefile

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

### Phase 6: Push và archive

```bash
# ============================================================
# Step 6.1: Tạo GitHub repo mới
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
# KHÔNG xóa — archive để giữ link references, issues, stars

gh repo archive openctemio/api --yes
gh repo archive openctemio/ui --yes
gh repo archive openctemio/agent --yes
gh repo archive openctemio/helm-charts --yes

# Update mỗi repo description để redirect
gh repo edit openctemio/api --description "⚠️ ARCHIVED — Moved to github.com/openctemio/openctemio/api"
gh repo edit openctemio/ui --description "⚠️ ARCHIVED — Moved to github.com/openctemio/openctemio/ui"
gh repo edit openctemio/agent --description "⚠️ ARCHIVED — Moved to github.com/openctemio/openctemio/agent"
```

---

## 6. CI/CD thiết kế

### 6.1 Path filtering strategy

GitHub Actions `paths` filter cho phép chỉ trigger workflow khi file ở path cụ thể thay đổi.

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

### 6.3 API CI workflow chi tiết

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

### 6.4 UI CI workflow chi tiết

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

**Không thay đổi** so với hiện tại — vì cả 3 repos đều dùng `main` + `develop` + feature branches.

---

## 7. Docker & Development workflow

### 7.1 docker-compose.yml — Thay đổi tối thiểu

```yaml
# Chỉ xóa sdk-go volume mount nếu không develop local
services:
  api:
    build:
      context: ./api          # ← KHÔNG đổi
      dockerfile: Dockerfile
      target: development
    volumes:
      - ./api:/app            # ← KHÔNG đổi
      # - ./sdk-go:/app/sdk-go  ← XÓA (sdk-go không còn ở local)

  ui:
    build:
      context: ./ui           # ← KHÔNG đổi
      dockerfile: Dockerfile
      target: development
    volumes:
      - ./ui:/app             # ← KHÔNG đổi
```

### 7.2 Dockerfiles — KHÔNG đổi

Dockerfiles trong `api/Dockerfile` và `ui/Dockerfile` reference paths relative to build context (`./api` hoặc `./ui`). Monorepo không ảnh hưởng.

### 7.3 Developer workflow mới

```bash
# Clone
git clone git@github.com:openctemio/openctemio.git
cd openctemio

# Start
docker compose up

# Develop feature touching both API + UI
git checkout -b feat/my-feature
# Edit api/... và ui/...
# API auto-reloads (air), UI auto-reloads (next dev)

# Test
make api-test
make ui-lint

# Commit — 1 atomic commit cho cả API + UI changes
git add api/internal/app/my_service.go ui/src/features/my-feature/
git commit -m "feat: add my-feature (API + UI)"

# PR
gh pr create --title "feat: add my-feature"
# → CI runs api-ci.yml AND ui-ci.yml (cả 2 paths thay đổi)
```

### 7.4 SDK-Go local development (khi cần)

Nếu cần develop sdk-go cùng lúc với api/agent:

```bash
# Clone sdk-go bên cạnh monorepo
git clone git@github.com:openctemio/sdk-go.git ../sdk-go

# Tạm thời update go.work
# go.work:
# use (
#     ./api
#     ./agent
#     ../sdk-go    ← thêm tạm
# )

# Hoặc dùng replace directive trong api/go.mod (nhớ xóa trước khi commit)
```

---

## 8. Go module strategy

### 8.1 Giữ nguyên module paths

```
api/go.mod    → module github.com/openctemio/api     (UNCHANGED)
agent/go.mod  → module github.com/openctemio/agent   (UNCHANGED)
```

**Tại sao không đổi thành `github.com/openctemio/openctemio/api`?**

1. **Breaking change**: Tất cả import paths trong code phải đổi
2. **Go proxy cache**: Module cũ vẫn cached, gây confusion
3. **sdk-go dependency**: sdk-go/agent `require github.com/openctemio/api` → phải update sdk-go
4. **Không cần thiết**: Go workspace (`go.work`) handle path mapping, module path không cần khớp repo path

### 8.2 go.work trong monorepo

```go
// go.work
go 1.26

use (
    ./api
    ./agent
)
```

- `go.work` giúp `api` và `agent` reference nhau locally
- sdk-go và ctis vẫn resolved từ Go proxy (remote modules)
- `go.work.sum` nên ở `.gitignore` (generated file)

### 8.3 Tương lai: Nếu muốn đổi module path

Nếu sau này quyết định đổi:

```bash
# 1. Update go.mod
cd api && go mod edit -module github.com/openctemio/openctemio/api

# 2. Update all imports
find api/ -name '*.go' -exec sed -i \
  's|github.com/openctemio/api/|github.com/openctemio/openctemio/api/|g' {} +

# 3. Test
cd api && go build ./...
```

**Khuyến nghị: Không đổi ở v0.2.0. Đổi ở v1.0.0 nếu cần (breaking change phù hợp với major version).**

---

## 9. Rủi ro và giải pháp

### R1: Git history merge conflicts

**Rủi ro**: `git subtree add` có thể conflict nếu root repo đã có files cùng path.

**Giải pháp**: Bắt đầu từ repo mới (empty). Không dùng root repo hiện tại (đã có untracked files và messy history).

**Probability**: Thấp (repo mới, empty initial commit).

### R2: CI chạy cả khi không cần

**Rủi ro**: Change README.md ở root trigger tất cả workflows.

**Giải pháp**: Path filters chỉ trigger khi files trong `api/**`, `ui/**`, hoặc `agent/**` thay đổi. Root files (README, LICENSE) không trigger bất kỳ CI nào.

**Edge case**: `go.work` thay đổi → trigger cả api-ci + agent-ci. Đây là đúng behavior vì workspace change có thể ảnh hưởng cả 2.

### R3: Repo size quá lớn

**Rủi ro**: Repo size tăng → clone chậm.

| Component | Size |
|-----------|------|
| api .git | 34MB |
| ui .git | 17MB |
| agent .git | 2.3MB |
| **Tổng .git** | **~53MB** |
| Source code (excl deps) | ~36MB |
| **Tổng clone size** | **~90MB** |

**Giải pháp**: 90MB là hoàn toàn bình thường. Kubernetes monorepo là 1.5GB+. Nếu cần, dùng `git clone --depth=1` cho CI.

### R4: Branch sync từ old repos

**Rủi ro**: Feature branches trên old repos (api/feat/decouple-sdk) mất.

**Giải pháp**:
1. Merge tất cả important branches vào develop **trước** khi migrate
2. Hoặc migrate branch bằng `git subtree`:
   ```bash
   git fetch api-origin feat/decouple-sdk
   git checkout -b feat/decouple-sdk
   git subtree add --prefix=api api-origin/feat/decouple-sdk
   ```

**Recommendation**: Merge `feat/decouple-sdk` vào develop trước. Đây là branch duy nhất quan trọng.

### R5: GitHub Issues/PRs trên old repos

**Rủi ro**: Links tới issues/PRs trên openctemio/api#123 sẽ vẫn hoạt động (archived, không xóa).

**Giải pháp**: Archive old repos — issues/PRs read-only nhưng URLs vẫn hoạt động. New issues tạo trên openctemio/openctemio.

### R6: Docker image names thay đổi

**Rủi ro**: Production đang pull `ghcr.io/openctemio/api:v0.1.8`.

**Giải pháp**: Docker image names **KHÔNG thay đổi**. CI build từ `./api` context, push lên cùng registry + image name. Monorepo = source code organization, không ảnh hưởng artifact names.

### R7: Dependabot/Renovate

**Rủi ro**: Dependabot cần config riêng cho Go + Node trong cùng repo.

**Giải pháp**:
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

Nếu monorepo gây vấn đề không lường trước:

```bash
# Old repos vẫn archived trên GitHub
# Unarchive:
gh repo unarchive openctemio/api
gh repo unarchive openctemio/ui
gh repo unarchive openctemio/agent

# Developers switch lại multi-repo workflow
# CI trên old repos vẫn configured
```

**Time to rollback**: < 5 phút (unarchive repos).

**Data loss**: Không — monorepo giữ history, old repos giữ nguyên.

---

## 11. Checklist thực hiện

### Pre-migration

- [ ] Merge tất cả pending feature branches (đặc biệt `feat/decouple-sdk`)
- [ ] Tag v0.1.8 cho api, ui, agent (bản release multi-repo cuối)
- [ ] Verify tất cả CI green trên main
- [ ] Backup: clone tất cả repos về local (bao gồm tất cả branches)
- [ ] Tạo GitHub repo: `openctemio/openctemio`

### Migration

- [ ] `git init` repo mới
- [ ] `git subtree add --prefix=api` từ api/main
- [ ] `git subtree add --prefix=ui` từ ui/main
- [ ] `git subtree add --prefix=agent` từ agent/main
- [ ] `git subtree add --prefix=deploy/helm` từ helm-charts/main
- [ ] Copy root files (docker-compose, go.work, docs, README, etc.)
- [ ] Tạo `.github/workflows/` (8 files)
- [ ] Tạo root Makefile
- [ ] Tạo root `.gitignore`
- [ ] Tạo root `CLAUDE.md`
- [ ] Tạo `.github/dependabot.yml`
- [ ] Update `docker-compose.yml` (xóa sdk-go volume)
- [ ] Update `go.work` (chỉ ./api, ./agent)

### Verification

- [ ] `git log --follow api/cmd/main.go` — verify full history
- [ ] `git log --follow ui/src/app/layout.tsx` — verify full history
- [ ] `docker compose up` — tất cả services start
- [ ] `make api-test` — API tests pass
- [ ] `make ui-lint` — UI lint pass
- [ ] `go build ./api/cmd/...` — API builds
- [ ] API curl health check: `curl http://localhost:8080/health`
- [ ] UI loads: `http://localhost:3000`

### Post-migration

- [ ] Push monorepo lên GitHub
- [ ] Tag v0.2.0 (first monorepo release)
- [ ] Archive old repos (api, ui, agent, helm-charts)
- [ ] Update old repo descriptions với redirect message
- [ ] Update docs/README với new repo URL
- [ ] Update CI secrets trên new repo (nếu cần)
- [ ] Update deploy scripts/helm values với new image references (nếu thay đổi)
- [ ] Thông báo team (nếu có)

---

## 12. Câu hỏi mở

### Q1: RFCs nên ở đâu?

**Option A**: Giữ ở `api/docs/rfcs/` (hiện tại) — api-specific
**Option B**: Move ra `docs/rfcs/` (root) — project-wide

**Khuyến nghị**: Option B — RFCs là project-wide decisions, không chỉ API.

### Q2: CLAUDE.md strategy

**Option A**: 1 file ở root
**Option B**: Root CLAUDE.md (chung) + api/CLAUDE.md (Go rules) + ui/CLAUDE.md (TS rules)

**Khuyến nghị**: Option B — Giữ nguyên per-project CLAUDE.md, thêm root file cho shared rules.

### Q3: Versioning scheme sau monorepo

**Option A**: Single version cho cả project (v0.2.0, v0.3.0...)
**Option B**: Per-component tags (api/v0.2.0, ui/v0.2.0)

**Khuyến nghị**: Option A — Monorepo = single version. Nếu cần biết component nào thay đổi, xem changelog.

### Q4: develop branch hay trunk-based?

**Hiện tại**: `main` + `develop` + feature branches (Gitflow-lite)
**Alternative**: Trunk-based (main only + feature branches)

**Khuyến nghị**: Giữ nguyên Gitflow-lite cho v0.2.x. Evaluate trunk-based khi team lớn hơn.

### Q5: Có cần lerna/nx/turborepo?

**Không.** Những tools này giải quyết problems của JavaScript monorepos với nhiều packages. OpenCTEM có:
- Go modules (built-in workspace support via `go.work`)
- 1 Next.js app (không phải multi-package JS)
- Makefile đủ cho orchestration

Thêm tooling = thêm complexity không cần thiết.

---

## Tham khảo

- [GitHub: About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) — CODEOWNERS cho path-based review assignment
- [GitHub Actions: paths filter](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onpushpull_requestpull_request_targetpathspaths-ignore)
- [git subtree tutorial](https://www.atlassian.com/git/tutorials/git-subtree)
- [Monorepo vs Multi-repo](https://github.com/joelparkerhenderson/monorepo-vs-polyrepo) — comprehensive analysis
