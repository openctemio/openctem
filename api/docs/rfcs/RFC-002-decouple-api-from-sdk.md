# RFC-002: Decouple API from SDK-Go — Extract CTIS Shared Types

- **Status**: Implemented — feature doc: [docs/architecture/api-ctis-decoupling.md](../architecture/api-ctis-decoupling.md)
- **Created**: 2026-04-15
- **Problem**: The API depends on SDK-Go (a client library, 50K lines). Every SDK update → the API's go.mod must be updated → rebuild → retest. The dependency points the wrong way: the backend source of truth depends on a client library.

---

## 1. Current state

```
API (backend, source of truth)
  └── depends on: github.com/openctemio/sdk-go v0.2.2
      ├── pkg/ctis           (2,416 lines — CTIS types)
      ├── pkg/shared/severity (217 lines — severity enum)
      ├── pkg/shared/fingerprint (429 lines — dedup hash)
      ├── pkg/chunk          (1,711 lines — payload chunking)
      ├── pkg/adapters       (5,497 lines — tool parsers)
      └── pkg/core           (~50 lines used — interfaces)

SDK-Go total: 50,711 lines
Used by the API: ~5,000 lines (10%)
```

### Practical problems

1. **SDK-Go tag v0.2.2** → the API must `go get sdk-go@v0.2.2` → rebuild → CI → deploy
2. SDK-Go adds a scanner wrapper (an agent feature) → the API must be retested too (transitive deps change)
3. An agent-only bug fix in the SDK → still triggers an API dependency update
4. 90% of the code the API pulls in is unused (scanners, platform client, transport...)

---

## 2. Detailed analysis: what needs to be extracted?

### 2.1 Dependency graph (current)

```
                    ┌─────────────────────────────┐
                    │         SDK-Go               │
                    │                               │
                    │  ctis ◄── chunk ◄── compress  │  ← circular cluster
                    │    ▲        ▲                  │
                    │    │        │                  │
                    │  severity  fingerprint         │  ← independent
                    │    ▲                           │
                    │    │                           │
                    │  adapters, core, scanners...   │  ← agent-only
                    └─────────────────────────────┘
                         ▲              ▲
                         │              │
                       API           Agent
```

### 2.2 Circular dependency blocker

```
chunk/manager.go ──→ compress/analyzer.go ──→ ctis/types.go
chunk/splitter.go ──→ ctis/types.go
chunk/types.go ──→ ctis/types.go
```

**If only ctis is extracted → chunk in SDK-Go does not compile** because ctis is gone.

### 2.3 What must be extracted together

| Package | Lines | Internal deps | External deps |
|---|---|---|---|
| `ctis` (types, sarif, recon_converter, normalize) | 3,719 | NONE | stdlib only |
| `shared/severity` | 217 | NONE | stdlib only |
| `shared/fingerprint` | 429 | NONE | stdlib only |
| `chunk` (manager, splitter, storage, types, config) | 1,711 | ctis, compress | google/uuid, modernc.org/sqlite |
| `compress` (compress.go only, analyzer stays) | 273 | NONE | klauspost/compress |
| **Total** | **6,349** | | |

### 2.4 compress/analyzer.go — a special case

`analyzer.go` imports ctis to estimate report size. The options:
- **A**: Move the analyzer into the ctis module (clean, but compress is split across two places)
- **B**: Move the whole compress package into the ctis module (simple, but pulls in the klauspost dependency)
- **C**: The analyzer stays in SDK-Go and imports the new ctis module (best — the analyzer is only an optimization helper)

**Chosen: C**: `compress.go` (core compression) + `analyzer.go` (ctis-dependent estimator) stay in SDK-Go. SDK-Go imports the ctis module for the analyzer. Chunk also stays in SDK-Go and imports the ctis module.

**→ Only ctis + severity + fingerprint need to be extracted (4,365 lines). Chunk and compress stay in SDK-Go and import the new module.**

---

## 3. New module design

### 3.1 Repository layout

```
openctemio/ctis/                            ← NEW repo
├── go.mod                                  ← module github.com/openctemio/ctis
├── LICENSE
├── README.md
│
├── types.go                                ← CTIS Report, Asset, Finding... (2,416 lines)
├── dependency_types.go                     ← Dependency types (65 lines)
├── sarif.go                                ← SARIF conversion (392 lines)
├── recon_converter.go                      ← Recon tool output conversion (776 lines)
├── normalize.go                            ← Asset name normalization (70 lines)
├── normalize_test.go                       ← Normalize tests
│
├── severity/                               ← Severity enum + parsing
│   ├── severity.go                         (217 lines)
│   └── severity_test.go                    (417 lines)
│
├── fingerprint/                            ← Finding dedup hash
│   ├── fingerprint.go                      (429 lines)
│   └── fingerprint_test.go                 (724 lines)
│
└── schemas/                                ← JSON schemas (moved from schemas/ repo)
    └── v1/
        ├── asset.json
        ├── finding.json
        ├── report.json
        ├── dependency.json
        ├── web3-asset.json
        └── web3-finding.json
```

### 3.2 go.mod — zero external dependencies

```go
module github.com/openctemio/ctis

go 1.22

// Zero external deps — stdlib only
// (google/uuid and sqlite stay with chunk in SDK-Go)
```

**Especially light**: it pulls in no external dependency at all. Stdlib only.

### 3.3 Import paths

```go
// API
import "github.com/openctemio/ctis"                // Report, Asset, Finding types
import "github.com/openctemio/ctis/severity"        // Severity enum
import "github.com/openctemio/ctis/fingerprint"     // Dedup hash

// SDK-Go (internal imports change)
import "github.com/openctemio/ctis"                // replaces pkg/ctis
import "github.com/openctemio/ctis/severity"        // replaces pkg/shared/severity
import "github.com/openctemio/ctis/fingerprint"     // replaces pkg/shared/fingerprint
// chunk, compress, adapters, core, scanners: stay in SDK-Go and import the ctis module
```

---

## 4. Edge Cases & Risks

### 4.1 Type drift between the ctis module and its consumers

| Scenario | Risk | Mitigation |
|---|---|---|
| ctis module adds a new field | LOW | JSON unmarshal ignores unknown fields → backward compatible |
| ctis module removes a field | HIGH | Agent sends the field, API does not parse it → data loss | **Semantic versioning**: breaking change = major version bump |
| ctis module changes a JSON tag | CRITICAL | Silent data loss | **CI test**: Agent → API integration test for every ctis release |
| ctis module changes a type (string→int) | CRITICAL | Unmarshal fail | **Semver + changelog** |

### 4.2 Version matrix

| ctis | SDK-Go | API | Agent | Compatible? |
|---|---|---|---|---|
| v1.0.0 | v0.3.0 (uses ctis v1.0.0) | v1.x (uses ctis v1.0.0) | v1.x (uses SDK v0.3.0) | YES — same ctis v1.0.0 |
| v1.1.0 (adds a field) | v0.3.0 (still ctis v1.0.0) | v1.x (upgrades to ctis v1.1.0) | v1.x (old SDK → ctis v1.0.0) | YES — an added field is backward compatible |
| v2.0.0 (breaking) | v0.4.0 (upgrade ctis v2.0.0) | v2.x (upgrade ctis v2.0.0) | v2.x (SDK v0.4.0) | Must upgrade together |

**Rule**: the ctis module uses **strict semantic versioning**:
- Patch (v1.0.x): bug fix, no struct changes
- Minor (v1.x.0): adds fields/types (backward compatible)
- Major (vX.0.0): changes/removes fields (breaking change — coordinate the upgrade)

### 4.3 Fingerprint consistency

| Scenario | Risk | Mitigation |
|---|---|---|
| API upgrades to ctis v1.1, Agent still uses v1.0 | Fingerprint hash v1.0 ≠ v1.1? | **RULE**: the fingerprint algorithm NEVER changes in a minor/patch release. Only new types are added; existing ones are not modified |
| Parallel Agent instances, different ctis versions | Same finding, different hash | **RULE**: no breaking changes in the fingerprint module. If a change is needed → add a separate `FingerprintV2()` |

### 4.4 Chunk protocol compatibility

Chunk stays in SDK-Go but imports the ctis types from the new module.

| Scenario | Risk | Mitigation |
|---|---|---|
| ctis v1.1 adds a field → chunk serializes differently | LOW | JSON marshal adds the field → API receives extra data → OK |
| ctis v2.0 changes a struct → chunk binary incompatible | HIGH | Upgrade SDK-Go + API together |

### 4.5 API updates of the ctis module version

```
BEFORE (with SDK-Go):
  SDK-Go adds a scanner → tag v0.2.3 → API must update → rebuild

AFTER (with the ctis module):
  SDK-Go adds a scanner → NO effect on the API
  ctis module adds a field → API go get ctis@v1.1.0 → rebuild
  ctis module does NOT change → API does NOT need a rebuild
```

**Lower update frequency**: the CTIS schema changes ~once a month. SDK-Go changes ~weekly (scanner updates).

### 4.6 Go workspace

```go
// go.work (updated)
go 1.26

use (
    ./agent
    ./api
    ./ctis      // NEW
    ./sdk-go
)

replace (
    github.com/openctemio/ctis => ./ctis
    github.com/openctemio/sdk-go => ./sdk-go
)
```

### 4.7 Adapters — where do they go?

The API imports `sdk-go/pkg/adapters` for SARIF/Trivy parsing. After the extraction:
- **Option A**: Adapters stay in SDK-Go and the API still imports SDK-Go for them → **does NOT solve the problem**
- **Option B**: Move adapters into the ctis module → ctis becomes too large and pulls in many deps
- **Option C**: Move adapters into the API (internal package) → **BEST** — the API owns the parsing logic

Adapters are used only by the API (the Agent does NOT import adapters). Copy the adapters into `api/internal/infra/adapters/`.

### 4.8 Core + Chunk — what does the API use?

The API imports `core` only for the `core.ChunkManager` interface (1 interface). Inline it into the handler.

The API imports `chunk` for `chunk.Manager` in the ingest handler. Options:
- **A**: The API still imports SDK-Go just for chunk → NOT clean
- **B**: Copy chunk into the API → duplicate maintenance
- **C**: Extract chunk into the ctis module → pulls in google/uuid + sqlite deps
- **D**: The API implements its own dechunk logic (receive chunks, reassemble) → **BEST long-term**, but high effort

**Pragmatic**: Phase 1 copies the adapters into the API and keeps the SDK-Go import for chunk. Phase 2 removes the chunk dependency.

---

## 5. Implementation Plan

### Phase 1: Create ctis module + move types (2 hours)

1. Create the repository `openctemio/ctis`
2. Copy: types.go, dependency_types.go, sarif.go, recon_converter.go, normalize.go
3. Copy: severity/, fingerprint/ (with tests)
4. Copy: schemas/v1/*.json from the schemas repository
5. Init go.mod (zero deps)
6. Run tests
7. Tag v1.0.0

### Phase 2: Update SDK-Go imports (1 hour)

1. SDK-Go: `go get github.com/openctemio/ctis@v1.0.0`
2. Replace 33 files: `sdk-go/pkg/ctis` → `ctis`
3. Replace: `sdk-go/pkg/shared/severity` → `ctis/severity`
4. Replace: `sdk-go/pkg/shared/fingerprint` → `ctis/fingerprint`
5. Keep original packages as thin re-exports (backward compat for external consumers):
   ```go
   // sdk-go/pkg/ctis/types.go — BACKWARD COMPAT WRAPPER
   package ctis
   import upstream "github.com/openctemio/ctis"
   type Report = upstream.Report
   type Asset = upstream.Asset
   type Finding = upstream.Finding
   // ... type aliases for all exported types
   ```
6. Tag SDK-Go v0.3.0

### Phase 3: Update API imports (1 hour)

1. API: `go get github.com/openctemio/ctis@v1.0.0`
2. Replace 22 files: import paths
3. Copy adapters into `api/internal/infra/adapters/`
4. Inline `core.ChunkManager` interface into handler
5. **Remove `github.com/openctemio/sdk-go` from API go.mod**
6. `go mod tidy`
7. Run all tests

### Phase 4: Update go.work + CI

1. Add `./ctis` to go.work `use` block
2. Add `replace github.com/openctemio/ctis => ./ctis`
3. Update CI pipelines for new module
4. Agent: no changes (imports SDK-Go v0.3.0 which re-exports ctis types)

---

## 6. Backward Compatibility

### SDK-Go consumers (Agent + any external)

SDK-Go v0.3.0 keeps original package paths as **type alias re-exports**:

```go
// sdk-go/pkg/ctis/compat.go
package ctis

import upstream "github.com/openctemio/ctis"

// Type aliases — existing consumers keep working
type Report = upstream.Report
type Asset = upstream.Asset
type Finding = upstream.Finding
type AssetType = upstream.AssetType
type Severity = upstream.Severity
// ... all 60+ exported types
```

Consumer code **zero changes**:
```go
// Agent code — UNCHANGED
import "github.com/openctemio/sdk-go/pkg/ctis"
report := &ctis.Report{...} // works, ctis.Report is alias to upstream.Report
```

### API

API switches to direct import:
```go
// BEFORE
import "github.com/openctemio/sdk-go/pkg/ctis"
// AFTER
import "github.com/openctemio/ctis"
```

---

## 7. Testing Strategy

| Test | Purpose |
|---|---|
| ctis module: `go test ./...` | All types, severity, fingerprint, normalize tests pass |
| SDK-Go: `go test ./...` | Verify re-export aliases work, all existing tests pass |
| API: `go test ./...` | Ingest pipeline works with new imports |
| **Integration**: Agent → API | Send CTIS report from Agent (SDK v0.3.0) → API (ctis v1.0.0) → verify data correct |
| **Fingerprint parity**: | Generate fingerprints from both SDK path and direct ctis path → must match |

---

## 8. Rollback Plan

If a problem is found after deployment:
1. API: revert import paths, add `sdk-go` back to go.mod
2. SDK-Go: revert to v0.2.2 (re-export aliases removed)
3. ctis module: keep as-is (no harm, just unused)

---

## 9. Result after the refactor

```
BEFORE:
  API ──depends──→ SDK-Go (50K lines, weekly updates)

AFTER:
  API ──depends──→ ctis (4K lines, updated ~once a month)
  
  SDK-Go ──depends──→ ctis (4K lines)
  Agent ──depends──→ SDK-Go (unchanged)
```

| Metric | Before | After |
|---|---|---|
| API external deps | SDK-Go 50K lines + 40 transitive deps | ctis 4K lines + 0 external deps |
| Update frequency | Weekly (SDK scanner updates) | ~Once a month (schema changes only) |
| API rebuild trigger | Any SDK change | Only when the CTIS schema changes |
| Backward compat | N/A | 100% — SDK re-exports type aliases |
| Agent changes | N/A | ZERO |

---

## 10. Open Questions

1. **Adapters, first version**: copy them into the API, or keep the SDK-Go import for adapters? (RFC recommends copy)
2. **Chunk phase 2**: when does the API implement its own dechunking? (possibly after the ctis module is stable)
3. **schemas/ repository**: archive it or merge it into ctis? (RFC recommends merge)
4. **ctis module publishing**: GitHub Packages or the Go proxy? (recommend the Go proxy for public access)
5. **NormalizeAssetName in ctis**: keep or remove? (Recommend keeping it — it is a pure function tied to the CTIS types, not business logic. The API has the full version, ctis a lightweight version)
