# RFC-002: Decouple API from SDK-Go — Extract CTIS Shared Types

- **Status**: Completed — feature doc: [docs/architecture/api-ctis-decoupling.md](../architecture/api-ctis-decoupling.md)
- **Created**: 2026-04-15
- **Problem**: API phụ thuộc SDK-Go (client library, 50K lines). Mỗi lần update SDK → phải update API go.mod → rebuild → retest. Ngược chiều dependency: backend source-of-truth phụ thuộc client lib.

---

## 1. Hiện trạng

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
API chỉ dùng: ~5,000 lines (10%)
```

### Vấn đề thực tế

1. **SDK-Go tag v0.2.2** → API phải `go get sdk-go@v0.2.2` → rebuild → CI → deploy
2. SDK-Go thêm scanner wrapper (agent feature) → API cũng phải retest (transitive deps change)
3. Agent-only bug fix trong SDK → vẫn trigger API dependency update
4. 90% code API pull về nhưng không dùng (scanners, platform client, transport...)

---

## 2. Phân tích kỹ: Gì cần extract?

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

**Nếu chỉ extract ctis → chunk trong SDK-Go không compile** vì ctis biến mất.

### 2.3 Phải extract cùng nhau

| Package | Lines | Phụ thuộc nội bộ | External deps |
|---|---|---|---|
| `ctis` (types, sarif, recon_converter, normalize) | 3,719 | KHÔNG | stdlib only |
| `shared/severity` | 217 | KHÔNG | stdlib only |
| `shared/fingerprint` | 429 | KHÔNG | stdlib only |
| `chunk` (manager, splitter, storage, types, config) | 1,711 | ctis, compress | google/uuid, modernc.org/sqlite |
| `compress` (compress.go only, analyzer stays) | 273 | KHÔNG | klauspost/compress |
| **Total** | **6,349** | | |

### 2.4 compress/analyzer.go — đặc biệt

`analyzer.go` import ctis để estimate report size. Có 2 lựa chọn:
- **A**: Move analyzer vào ctis module (clean, nhưng compress split thành 2 nơi)
- **B**: Move cả compress package vào ctis module (simple, nhưng kéo thêm klauspost dep)
- **C**: Analyzer stays in SDK-Go, import từ ctis module mới (best — analyzer chỉ là optimization helper)

**Chọn C**: `compress.go` (core compression) + `analyzer.go` (ctis-dependent estimator) ở SDK-Go. SDK-Go import ctis module cho analyzer. Chunk cũng ở SDK-Go, import ctis module.

**→ Chỉ cần extract: ctis + severity + fingerprint (4,365 lines). Chunk và compress ở lại SDK-Go, import từ module mới.**

---

## 3. Thiết kế module mới

### 3.1 Cấu trúc repo

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

// Zero external deps — chỉ stdlib
// (google/uuid, sqlite ở lại với chunk trong SDK-Go)
```

**Đặc biệt nhẹ**: Không pull bất kỳ external dep nào. Chỉ stdlib.

### 3.3 Import paths

```go
// API
import "github.com/openctemio/ctis"                // Report, Asset, Finding types
import "github.com/openctemio/ctis/severity"        // Severity enum
import "github.com/openctemio/ctis/fingerprint"     // Dedup hash

// SDK-Go (thay đổi internal imports)
import "github.com/openctemio/ctis"                // thay cho pkg/ctis
import "github.com/openctemio/ctis/severity"        // thay cho pkg/shared/severity
import "github.com/openctemio/ctis/fingerprint"     // thay cho pkg/shared/fingerprint
// chunk, compress, adapters, core, scanners: ở lại SDK-Go, import ctis module
```

---

## 4. Edge Cases & Risks

### 4.1 Type drift giữa ctis module và consumers

| Scenario | Risk | Mitigation |
|---|---|---|
| ctis module thêm field mới | LOW | JSON unmarshal bỏ qua unknown fields → backward compatible |
| ctis module xoá field | HIGH | Agent gửi field, API không parse → data loss | **Semantic versioning**: breaking change = major version bump |
| ctis module đổi JSON tag | CRITICAL | Silent data loss | **CI test**: integration test Agent → API với mỗi ctis release |
| ctis module đổi type (string→int) | CRITICAL | Unmarshal fail | **Semver + changelog** |

### 4.2 Version matrix

| ctis | SDK-Go | API | Agent | Tương thích? |
|---|---|---|---|---|
| v1.0.0 | v0.3.0 (uses ctis v1.0.0) | v1.x (uses ctis v1.0.0) | v1.x (uses SDK v0.3.0) | YES — cùng ctis v1.0.0 |
| v1.1.0 (thêm field) | v0.3.0 (vẫn ctis v1.0.0) | v1.x (upgrade ctis v1.1.0) | v1.x (SDK cũ → ctis v1.0.0) | YES — thêm field backward compat |
| v2.0.0 (breaking) | v0.4.0 (upgrade ctis v2.0.0) | v2.x (upgrade ctis v2.0.0) | v2.x (SDK v0.4.0) | Phải upgrade cùng lúc |

**Quy tắc**: ctis module dùng **semantic versioning nghiêm ngặt**:
- Patch (v1.0.x): bug fix, no struct changes
- Minor (v1.x.0): thêm fields/types (backward compatible)
- Major (vX.0.0): đổi/xoá fields (breaking change — coordinate upgrade)

### 4.3 Fingerprint consistency

| Scenario | Risk | Mitigation |
|---|---|---|
| API upgrade ctis v1.1, Agent vẫn dùng v1.0 | Fingerprint hash v1.0 ≠ v1.1? | **RULE**: fingerprint algorithm KHÔNG BAO GIỜ thay đổi trong minor/patch. Chỉ thêm mới type, không sửa existing |
| Parallel Agent instances, different ctis versions | Cùng finding, khác hash | **RULE**: fingerprint module không breaking changes. Nếu cần sửa → tạo `FingerprintV2()` riêng |

### 4.4 Chunk protocol compatibility

Chunk ở lại SDK-Go nhưng import ctis types từ module mới.

| Scenario | Risk | Mitigation |
|---|---|---|
| ctis v1.1 thêm field → chunk serialize khác | LOW | JSON marshal thêm field → API nhận thêm data → OK |
| ctis v2.0 đổi struct → chunk binary incompatible | HIGH | Coordinate upgrade SDK-Go + API cùng lúc |

### 4.5 API update ctis module version

```
TRƯỚC (với SDK-Go):
  SDK-Go thêm scanner → tag v0.2.3 → API phải update → rebuild

SAU (với ctis module):
  SDK-Go thêm scanner → KHÔNG ảnh hưởng API
  ctis module thêm field → API go get ctis@v1.1.0 → rebuild
  ctis module KHÔNG thay đổi → API KHÔNG cần rebuild
```

**Tần suất update giảm**: CTIS schema thay đổi ~1 lần/tháng. SDK-Go thay đổi ~hàng tuần (scanner updates).

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

### 4.7 Adapters — ở đâu?

API import `sdk-go/pkg/adapters` cho SARIF/Trivy parsing. Sau extract:
- **Phương án A**: Adapters ở lại SDK-Go, API vẫn import SDK-Go cho adapters → **KHÔNG giải quyết vấn đề**
- **Phương án B**: Move adapters vào ctis module → ctis trở thành quá lớn, kéo theo nhiều deps
- **Phương án C**: Move adapters vào API (internal package) → **BEST** — API owns parsing logic

Adapters chỉ dùng bởi API (Agent KHÔNG import adapters). Copy adapters vào `api/internal/infra/adapters/`.

### 4.8 Core + Chunk — API dùng gì?

API import `core` chỉ cho `core.ChunkManager` interface (1 interface). Inline vào handler.

API import `chunk` cho `chunk.Manager` trong ingest handler. Phương án:
- **A**: API vẫn import SDK-Go chỉ cho chunk → KHÔNG clean
- **B**: Copy chunk vào API → duplicate maintenance
- **C**: Extract chunk vào ctis module → kéo thêm google/uuid + sqlite deps
- **D**: API tự implement dechunk logic (nhận chunks, reassemble) → **BEST cho long-term** nhưng effort cao

**Pragmatic**: Phase 1 copy adapters vào API, giữ SDK-Go import cho chunk. Phase 2 remove chunk dependency.

---

## 5. Implementation Plan

### Phase 1: Create ctis module + move types (2 hours)

1. Tạo repo `openctemio/ctis`
2. Copy: types.go, dependency_types.go, sarif.go, recon_converter.go, normalize.go
3. Copy: severity/, fingerprint/ (with tests)
4. Copy: schemas/v1/*.json từ schemas repo
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

Nếu phát hiện vấn đề sau deploy:
1. API: revert import paths, add `sdk-go` back to go.mod
2. SDK-Go: revert to v0.2.2 (re-export aliases removed)
3. ctis module: keep as-is (no harm, just unused)

---

## 9. Kết quả sau refactor

```
TRƯỚC:
  API ──depends──→ SDK-Go (50K lines, update hàng tuần)

SAU:
  API ──depends──→ ctis (4K lines, update ~1 lần/tháng)
  
  SDK-Go ──depends──→ ctis (4K lines)
  Agent ──depends──→ SDK-Go (unchanged)
```

| Metric | Trước | Sau |
|---|---|---|
| API external deps | SDK-Go 50K lines + 40 transitive deps | ctis 4K lines + 0 external deps |
| Update frequency | Hàng tuần (SDK scanner updates) | ~1 lần/tháng (schema changes only) |
| API rebuild trigger | Bất kỳ SDK change | Chỉ khi CTIS schema thay đổi |
| Backward compat | N/A | 100% — SDK re-exports type aliases |
| Agent changes | N/A | ZERO |

---

## 10. Open Questions

1. **Adapters phiên bản 1**: Copy vào API hay giữ SDK-Go import cho adapters? (RFC recommends copy)
2. **Chunk phase 2**: Khi nào tự implement dechunk trong API? (có thể sau khi ctis module stable)
3. **schemas/ repo**: Archive hay merge vào ctis? (RFC recommends merge)
4. **ctis module publish**: GitHub Packages hay Go proxy? (recommend Go proxy cho public access)
5. **NormalizeAssetName trong ctis**: Giữ hay xoá? (Recommend giữ — nó là pure function liên quan đến CTIS types, không phải business logic. API có full version, ctis có lightweight version)
