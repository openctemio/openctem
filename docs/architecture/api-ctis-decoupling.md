# API-CTIS Decoupling

> **Status**: Production-ready | **Origin**: RFC-002 (completed 2026-04-15)

## Overview

API imports CTIS types from a standalone lightweight module (`github.com/openctemio/ctis`) instead of the full SDK-Go (50K lines). This eliminates unnecessary dependency coupling between the backend and client library.

## Architecture

```
BEFORE:
  API ──→ SDK-Go (50K lines, 40 deps, weekly updates)

AFTER:
  API ──→ ctis module (4K lines, zero deps, monthly updates)
  
  SDK-Go: unchanged (Agent still imports SDK-Go)
  Agent:  unchanged
```

## Why

| Problem | Impact |
|---|---|
| SDK-Go adds scanner wrapper → API must rebuild | Unnecessary CI/CD cycles |
| SDK-Go bumps transitive dep → API go.sum changes | Noisy diffs, false alerts |
| 90% of SDK-Go code unused by API | Bloated dependency tree |
| Agent bug fix → API forced to retest | Wrong dependency direction |

## CTIS Module (`github.com/openctemio/ctis`)

**Zero external dependencies** — stdlib only.

| Package | Contents | Lines |
|---|---|---|
| `ctis` (root) | Report, Asset, Finding, DataFlow structs (60+) | 2,416 |
| `ctis/severity` | Severity enum, parsing, comparison | 217 |
| `ctis/fingerprint` | SHA256 finding dedup hash | 429 |
| `schemas/v1/` | JSON Schema definitions (6 files) | N/A |

### Installation

```go
import (
    "github.com/openctemio/ctis"
    "github.com/openctemio/ctis/severity"
    "github.com/openctemio/ctis/fingerprint"
)
```

## What Changed in API

### Imports replaced (22 files)

```
BEFORE: "github.com/openctemio/sdk-go/pkg/ctis"
AFTER:  "github.com/openctemio/ctis"

BEFORE: "github.com/openctemio/sdk-go/pkg/shared/severity"
AFTER:  "github.com/openctemio/ctis/severity"

BEFORE: "github.com/openctemio/sdk-go/pkg/shared/fingerprint"
AFTER:  "github.com/openctemio/ctis/fingerprint"
```

### Adapters copied into API

Scanner output adapters (SARIF, Trivy, Nuclei, Semgrep, Gitleaks, Vuls) moved from SDK-Go into `internal/infra/adapters/`. Only API uses these — Agent does not.

### ChunkData inlined

`chunk.ChunkData` struct (8 fields) inlined into `ingest_handler.go`. Only used for JSON deserialization of chunked uploads.

### SDK-Go removed from go.mod

```
// go.mod — SDK-Go is GONE
require github.com/openctemio/ctis v1.0.0
// NO github.com/openctemio/sdk-go
```

## Versioning Strategy

| Version bump | Meaning | API action |
|---|---|---|
| Patch (v1.0.x) | Bug fix, no struct changes | `go get ctis@latest` |
| Minor (v1.x.0) | New fields/types added | `go get ctis@latest` (backward compatible) |
| Major (vX.0.0) | Breaking: fields renamed/removed | Coordinate with Agent upgrade |

**Key rule**: Fingerprint algorithm NEVER changes in minor/patch (would break dedup).

## Type Sync

API's ctis types and SDK-Go's ctis types are **copies from the same source**. CI verifies parity:
- ctis module is the single source of truth
- SDK-Go still has its own copy in `pkg/ctis/` (for Agent backward compat)
- Both must serialize/deserialize identically (same JSON tags)

## Key Files

| File | Purpose |
|---|---|
| `go.mod` | `require github.com/openctemio/ctis v1.0.0` |
| `internal/infra/adapters/` | Copied scanner adapters (SARIF, Trivy, etc.) |
| `internal/infra/http/handler/ingest_handler.go` | ChunkData inlined |
| `internal/app/ingest/` | All processors use `ctis` types |

## Related

- [CTIS Module Repository](https://github.com/openctemio/ctis)
- [RFC-002](../rfcs/RFC-002-decouple-api-from-sdk.md) — original design document
