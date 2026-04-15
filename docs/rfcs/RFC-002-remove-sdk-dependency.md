# RFC-002: Remove API Dependency on SDK-Go

- **Status**: Draft
- **Created**: 2026-04-15
- **Problem**: API depends on sdk-go (client library). Every SDK update forces API rebuild/retest.

## Current State

API imports 6 SDK-Go packages across 11 files:

| SDK Package | Used For | Lines to Copy | Target in API |
|---|---|---|---|
| `ctis` | CTIS types (Report, Asset, Finding structs) | ~2,400 | `pkg/ctis/` (NEW) |
| `shared/severity` | Severity enum + parsing | ~100 | `pkg/ctis/severity.go` |
| `shared/fingerprint` | Finding dedup hash | ~80 | `pkg/ctis/fingerprint.go` |
| `adapters` | SARIF/Trivy/Semgrep parsers | ~5,500 | `pkg/ctis/adapters/` |
| `chunk` | Large payload chunking | ~200 | `internal/infra/http/handler/` (inline) |
| `core` | Scanner interfaces | ~50 used | Remove (unused after move) |

## Plan

### Step 1: Copy `ctis` types into API (pkg/ctis/)

```
api/pkg/ctis/           ← NEW (copy from sdk-go/pkg/ctis/)
├── types.go            ← Asset, Finding, Report, etc. structs
├── severity.go         ← Severity enum (from shared/severity)
├── fingerprint.go      ← Hash function (from shared/fingerprint)
└── adapters/           ← SARIF, Trivy, Semgrep parsers
    ├── sarif.go
    ├── trivy.go
    ├── semgrep.go
    ├── nuclei.go
    └── gitleaks.go
```

### Step 2: Update all imports

```
BEFORE: "github.com/openctemio/sdk-go/pkg/ctis"
AFTER:  "github.com/openctemio/api/pkg/ctis"
```

11 files to update (find+replace).

### Step 3: Inline chunk manager

The `chunk` package is only used in ingest_handler.go for large payload handling.
Copy the ~200 lines into the handler or create `internal/infra/http/chunk/`.

### Step 4: Remove `core` import

Only used for `core.ChunkManager` interface — replaced by local type in step 3.

### Step 5: Remove sdk-go from go.mod

```
go mod edit -droprequire github.com/openctemio/sdk-go
go mod tidy
```

### Step 6: Keep SDK-Go types in sync

SDK-Go keeps its own copy of CTIS types for Agent use.
When CTIS schema changes:
1. Update `api/pkg/ctis/` (source of truth)
2. Update `sdk-go/pkg/ctis/` (copy for Agent)

Or: generate both from `schemas/ctis/v1/*.json` (future improvement).

## Impact

- API: 11 files import path change + 2 packages copied
- SDK-Go: NO changes (Agent still imports SDK-Go normally)
- Agent: NO changes
- UI: NO changes
- Breaking: NONE (internal refactor only)

## Effort: ~2 hours
