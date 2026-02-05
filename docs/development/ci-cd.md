# CI/CD

## GitHub Actions Workflows

### Overview

```
.github/workflows/
├── ci.yml              # Continuous Integration (PR + push)
├── docker-publish.yml  # Docker image publishing (tags)
└── security.yml        # Security scanning (scheduled + push)
```

### Workflow Triggers

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR to main/develop, push to main/develop | Quality checks, tests, build |
| `docker-publish.yml` | Tag push (`v*`), manual dispatch | Build & publish Docker images |
| `security.yml` | Weekly schedule, push to main | Security vulnerability scanning |

---

## ci.yml - Continuous Integration

Runs quality checks, tests, and builds on every PR and push.

### PR Workflow (Fast)
```
quality ─┐
         ├── Done (no build on PR)
test ────┘
```

### Push Workflow (Full)
```
quality ─┐
         ├── build ── Done
test ────┘
```

### Jobs

1. **quality** - Runs lint and type checks
   - `golangci-lint` for code quality
   - Format validation

2. **test** - Runs unit and integration tests
   - Uses PostgreSQL service container
   - Runs `make test`

3. **build** - Builds the binary (only on push, not PR)
   - Compiles `cmd/server`
   - Validates build works

---

## docker-publish.yml - Docker Image Publishing

Builds and publishes multi-platform Docker images for 3 components:
- **api** - Main API server
- **migrations** - Database migrations
- **seed** - Database seeding

### Trigger

- **Tag push**: `v*` (e.g., `v0.1.0`, `v0.1.0-staging`)
- **Manual dispatch**: With version and environment inputs

### Environment Detection

| Tag Pattern | Environment | Image Tags |
|-------------|-------------|------------|
| `v0.1.0` | production | `v0.1.0`, `latest` |
| `v0.1.0-staging` | staging | `v0.1.0-staging`, `staging-latest` |

### Optimized Parallel Build Strategy

```
prepare ─────────────────────────────────────────────────────┐
                                                             │
build (linux/amd64) ────────────────────────────────────────┐│
├── Build API → push digest                                 ││
├── Build Migrations → push digest                          ├┴── merge
└── Build Seed → push digest                                │    ├── Create API manifest
                                                            │    ├── Create Migrations manifest
build (linux/arm64) ────────────────────────────────────────┘    └── Create Seed manifest
├── Build API → push digest
├── Build Migrations → push digest
└── Build Seed → push digest
```

### Key Optimizations

1. **Parallel Platform Builds**
   - `linux/amd64` and `linux/arm64` build simultaneously
   - ~50% faster than sequential builds

2. **Push by Digest**
   - Each platform pushes immediately after build
   - No waiting for other platforms to complete

3. **Scoped Cache**
   - Separate cache per image and platform
   - Example: `scope=api-linux/amd64`, `scope=migrations-linux/arm64`
   - Prevents cache conflicts and improves hit rate

4. **Multi-Platform Manifest**
   - Final step merges all digests into a single manifest
   - Users get the correct image for their platform automatically

### Published Images

| Image | Description |
|-------|-------------|
| `exploopio/api` | Main API server |
| `exploopio/migrations` | Database migrations runner |
| `exploopio/seed` | Database seeding utility |

### Manual Trigger

```bash
# Via GitHub CLI
gh workflow run docker-publish.yml \
  -f version=v0.1.1 \
  -f environment=staging

# Via GitHub UI
# Actions → Docker Publish → Run workflow
```

---

## security.yml - Security Scanning

Scans for vulnerabilities in dependencies and code.

### Schedule

- **Weekly**: Every Sunday at midnight UTC
- **On push**: To main branch

### Tools

- **Trivy**: Filesystem and dependency scanning
- **CodeQL**: Static analysis for security issues
- **gosec**: Go-specific security checks

---

## Makefile Commands

```bash
# Build
make build              # Build server binary

# Test
make test               # Run unit tests
make test-integration   # Run integration tests
make test-coverage      # Generate coverage report

# Lint
make lint               # Run golangci-lint

# Docker
make docker-build       # Build local Docker image
make docker-up          # Start docker-compose
make docker-down        # Stop docker-compose

# Migrations
make migrate-up         # Apply migrations
make migrate-down       # Rollback migrations

# Generate
make swagger            # Generate Swagger docs
make generate           # Generate mocks, etc.
```

---

## Branch Strategy

```
main (production)
├── develop (staging)
│   ├── feature/xxx
│   └── bugfix/xxx
└── hotfix/xxx
```

### Deployment Flow

1. **Feature Development**
   ```
   feature/xxx → PR to develop → CI passes → Merge
   ```

2. **Staging Release**
   ```
   Tag v0.1.0-staging → Docker publish → Deploy to staging
   ```

3. **Production Release**
   ```
   develop → PR to main → Merge → Tag v0.1.0 → Docker publish → Deploy to production
   ```

---

## Secrets Required

| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token |

---

## Troubleshooting

### Build Failures

1. **Cache issues**: Clear GHA cache in repo settings
2. **QEMU errors**: Update `docker/setup-qemu-action` version
3. **Timeout**: Increase timeout in workflow or optimize Dockerfile

### Image Not Found

1. Check workflow run status in Actions tab
2. Verify tag format matches `v*` pattern
3. Check Docker Hub for published images

### Multi-Platform Issues

1. Ensure QEMU is set up before Buildx
2. Check platform-specific Dockerfile commands
3. Verify base images support both amd64 and arm64
