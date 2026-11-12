# API-CTIS Decoupling

> **Status**: Production-ready | **Origin**: RFC-002 (completed 2026-04-15)

## Overview

API imports CTIS types from a standalone lightweight module (`github.com/openctemio/ctis/v2`) instead of the full SDK-Go (50K lines). This eliminates unnecessary dependency coupling between the backend and client library.

## Architecture

```
BEFORE:
  API ──→ SDK-Go (50K lines, 40 deps, weekly updates)

AFTER:
  API ──→ ctis module (4K lines, zero deps, monthly updates)
  
  SDK-Go: unchanged (the sensor imports SDK-Go)
  Sensor: unchanged
```

## Why

| Problem | Impact |
|---|---|
| SDK-Go adds scanner wrapper → API must rebuild | Unnecessary CI/CD cycles |
| SDK-Go bumps transitive dep → API go.sum changes | Noisy diffs, false alerts |
| 90% of SDK-Go code unused by API | Bloated dependency tree |
| Sensor bug fix → API forced to retest | Wrong dependency direction |

## CTIS Module (`github.com/openctemio/ctis/v2`)

**Zero external dependencies** — stdlib only.

| Package | Contents | Lines |
|---|---|---|
| `ctis` (root) | Report, Asset, Finding, DataFlow structs (60+) | 2,416 |
| `ctis/severity` | Severity enum, parsing, comparison | 217 |
| `ctis/fingerprint` | SHA256 finding dedup hash | 429 |
| `schemas/v2/` | JSON Schema definitions | N/A |

The orchestration packages that used to sit in this module (`capability`,
`tooloption`, `settings`, `outcome`, `politeness`, `edgeprotect`, `addrscope`,
`source`, and `transfer`, its own module) moved to `github.com/openctemio/contract`
when CTIS 2.0 shipped. The platform accepts CTIS 2.x only (media type
`application/vnd.ctis+json; version=2.0`); see
[ctis-receiver.md](ctis-receiver.md).

### Installation

```go
import (
    "github.com/openctemio/ctis/v2"
    "github.com/openctemio/ctis/v2/severity"
    "github.com/openctemio/ctis/v2/fingerprint"
)
```

## What Changed in API

### Imports replaced (22 files)

```
BEFORE: "github.com/openctemio/sdk-go/pkg/ctis"
AFTER:  "github.com/openctemio/ctis" (v2 since CTIS 2.0: "github.com/openctemio/ctis/v2")

BEFORE: "github.com/openctemio/sdk-go/pkg/shared/severity"
AFTER:  "github.com/openctemio/ctis/severity"

BEFORE: "github.com/openctemio/sdk-go/pkg/shared/fingerprint"
AFTER:  "github.com/openctemio/ctis/fingerprint"
```

### Scanner output

Scanner output is converted to CTIS on the sensor (sdk-go parsers). The API
receives CTIS reports over the sensor protocol v2 and file imports through
`internal/app/findingimport`; it carries no copy of the sdk-go scanner adapters.

### SDK-Go removed from go.mod

```
// server/go.mod: no sdk-go
require github.com/openctemio/ctis/v2 vX.Y.Z
require github.com/openctemio/contract vX.Y.Z
// NO github.com/openctemio/sdk-go
```

## Versioning Strategy

| Version bump | Meaning | API action |
|---|---|---|
| Patch (v2.0.x) | Bug fix, no struct changes | `go get ctis@latest` |
| Minor (v2.x.0) | New fields/types added | `go get ctis@latest` (backward compatible) |
| Major (vX.0.0) | Breaking: fields renamed/removed | Coordinate with a sensor and sdk-go release |

**Key rule**: Fingerprint algorithm NEVER changes in minor/patch (would break dedup).

## Type Sync

API's ctis types and SDK-Go's ctis types are **copies from the same source**. CI verifies parity:
- ctis module is the single source of truth
- sdk-go and the sensor import the same module
- Both must serialize/deserialize identically (same JSON tags)

## Key Files

| File | Purpose |
|---|---|
| `server/go.mod` | `require github.com/openctemio/ctis` |
| `internal/app/ingest/` | All processors use `ctis` types |

## Related

- [CTIS Module Repository](https://github.com/openctemio/ctis)
- [RFC-002](../rfcs/RFC-002-decouple-api-from-sdk.md) — original design document
