# Pre-commit Security Hooks

Guide for configuring and using security pre-commit hooks for OpenCTEM API.

## Installation

```bash
# Install all tools and hooks
make pre-commit-install
```

## Security Hooks

| Hook | Purpose |
|------|---------|
| **Gitleaks** | Detect secrets (API keys, passwords, tokens) |
| **Golangci-lint** | Static analysis with gosec (security vulnerabilities) |
| **Trivy** | Scan vulnerabilities in dependencies |
| **Checkov** | IaC security scan for Dockerfile |
| **Hadolint** | Dockerfile best practices |

## Manual Execution

```bash
# Run all hooks
make pre-commit-run

# Run full security scan
make security-scan

# Run only gitleaks
make gitleaks
```

## Configuring False Positives & Ignores

### 1. Gitleaks - Ignore Secrets

**Configuration file:** `.gitleaks.toml`

#### Ignore files or paths

```toml
[allowlist]
paths = [
    # Ignore test files
    '''.*_test\.go$''',
    # Ignore example files
    '''.*\.example$''',
    # Ignore specific file
    '''internal/config/defaults\.go$''',
    # Ignore entire directory
    '''testdata/.*''',
]
```

#### Ignore specific patterns (false positive)

```toml
[allowlist]
regexes = [
    # Ignore placeholder values
    '''(?i)(example|sample|test|fake|placeholder)''',
    '''changeme''',
    # Ignore specific variable pattern
    '''MY_SPECIFIC_VAR=.*''',
]
```

#### Ignore inline in code

```go
// gitleaks:allow
const TestToken = "fake-token-for-testing"
```

#### Ignore specific commits

```toml
[allowlist]
commits = [
    "abc123def456...",  # commit hash
]
```

---

### 2. Golangci-lint with Gosec

**Configuration file:** `.golangci.yml`

#### Ignore specific rules

```yaml
linters-settings:
  gosec:
    excludes:
      - G101  # Ignore "hardcoded credentials" false positives
      - G104  # Ignore unhandled errors
      - G402  # Allow InsecureSkipVerify
```

#### Ignore files or paths

```yaml
issues:
  exclude-rules:
    # Ignore gosec in test files
    - path: _test\.go
      linters:
        - gosec

    # Ignore specific file
    - path: internal/legacy/old_code\.go
      linters:
        - gosec
```

#### Ignore inline in code

```go
// nolint:gosec
password := "admin123"  // This is a test value

// Or ignore multiple linters
// nolint:gosec,errcheck
```

---

### 3. Trivy - Ignore Vulnerabilities

**Create file:** `.trivyignore`

```
# Ignore specific CVE
CVE-2023-12345

# Ignore with reason
CVE-2023-67890  # Won't fix - not applicable to our use case
```

**Or ignore inline via command:**

```bash
trivy fs --skip-files="internal/legacy/*" .
trivy fs --skip-dirs="vendor,testdata" .
```

---

### 4. Checkov - Ignore IaC Checks

**Create file:** `.checkov.yaml`

```yaml
skip-check:
  - CKV_DOCKER_2  # Ensure HEALTHCHECK
  - CKV_DOCKER_3  # Ensure USER is set
```

**Or inline in Dockerfile:**

```dockerfile
# checkov:skip=CKV_DOCKER_2: Health check handled by orchestrator
FROM golang:1.25-alpine
```

---

### 5. Hadolint - Ignore Dockerfile Rules

**Inline ignore:**

```dockerfile
# hadolint ignore=DL3008,DL3018
RUN apt-get update && apt-get install -y curl
```

**Create file:** `.hadolint.yaml`

```yaml
ignored:
  - DL3008  # Pin versions in apt-get
  - DL3018  # Pin versions in apk add

trustedRegistries:
  - docker.io
  - gcr.io
```

---

## Bypass When Necessary

> ⚠️ **Warning**: Only use when absolutely necessary!

```bash
# Bypass pre-commit for a single commit (NOT recommended)
git commit --no-verify -m "Your message"

# Run hooks except specific ones
SKIP=gitleaks,trivy-fs git commit -m "Your message"
```
