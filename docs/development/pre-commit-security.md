# Pre-commit Security Hooks

Hướng dẫn cấu hình và sử dụng pre-commit hooks bảo mật cho Rediver API.

## Cài đặt

```bash
# Cài đặt tất cả công cụ và hooks
make pre-commit-install
```

## Các Security Hooks

| Hook | Mục đích |
|------|----------|
| **Gitleaks** | Phát hiện secrets (API keys, passwords, tokens) |
| **Golangci-lint** | Static analysis với gosec (security vulnerabilities) |
| **Trivy** | Scan vulnerabilities trong dependencies |
| **Checkov** | IaC security scan cho Dockerfile |
| **Hadolint** | Dockerfile best practices |

## Chạy thủ công

```bash
# Chạy tất cả hooks
make pre-commit-run

# Chạy full security scan
make security-scan

# Chỉ chạy gitleaks
make gitleaks
```

## Cấu hình False Positive & Ignore

### 1. Gitleaks - Ignore Secrets

**File cấu hình:** `.gitleaks.toml`

#### Ignore file hoặc đường dẫn

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

#### Ignore pattern cụ thể (false positive)

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

#### Ignore inline trong code

```go
// gitleaks:allow
const TestToken = "fake-token-for-testing"
```

#### Ignore commit cụ thể

```toml
[allowlist]
commits = [
    "abc123def456...",  # commit hash
]
```

---

### 2. Golangci-lint with Gosec

**File cấu hình:** `.golangci.yml`

#### Ignore rule cụ thể

```yaml
linters-settings:
  gosec:
    excludes:
      - G101  # Ignore "hardcoded credentials" false positives
      - G104  # Ignore unhandled errors
      - G402  # Allow InsecureSkipVerify
```

#### Ignore file hoặc path

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

#### Ignore inline trong code

```go
// nolint:gosec
password := "admin123"  // This is a test value

// Hoặc ignore nhiều linters
// nolint:gosec,errcheck
```

---

### 3. Trivy - Ignore Vulnerabilities

**Tạo file:** `.trivyignore`

```
# Ignore specific CVE
CVE-2023-12345

# Ignore with reason
CVE-2023-67890  # Won't fix - not applicable to our use case
```

**Hoặc ignore inline qua command:**

```bash
trivy fs --skip-files="internal/legacy/*" .
trivy fs --skip-dirs="vendor,testdata" .
```

---

### 4. Checkov - Ignore IaC Checks

**Tạo file:** `.checkov.yaml`

```yaml
skip-check:
  - CKV_DOCKER_2  # Ensure HEALTHCHECK
  - CKV_DOCKER_3  # Ensure USER is set
```

**Hoặc inline trong Dockerfile:**

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

**Tạo file:** `.hadolint.yaml`

```yaml
ignored:
  - DL3008  # Pin versions in apt-get
  - DL3018  # Pin versions in apk add

trustedRegistries:
  - docker.io
  - gcr.io
```

---

## Bypass khi cần thiết

> ⚠️ **Cảnh báo**: Chỉ sử dụng khi thực sự cần thiết!

```bash
# Bypass pre-commit cho một commit (KHÔNG khuyến khích)
git commit --no-verify -m "Your message"

# Chạy hooks trừ một số hooks cụ thể
SKIP=gitleaks,trivy-fs git commit -m "Your message"
```
