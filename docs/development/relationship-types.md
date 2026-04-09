# Relationship Types — Codegen & Workflow Guide

> Audience: backend + frontend developers who need to add, modify, or
> remove asset relationship types. If you have never touched the
> relationship registry before, **read the [Quickstart](#quickstart)
> first** then come back to the rest as needed.

## Table of contents

- [What this is and why it exists](#what-this-is-and-why-it-exists)
- [The 30-second mental model](#the-30-second-mental-model)
- [Quickstart](#quickstart)
- [File map — what lives where](#file-map--what-lives-where)
- [YAML schema reference](#yaml-schema-reference)
- [Workflows](#workflows)
  - [Adding a new relationship type](#adding-a-new-relationship-type)
  - [Modifying an existing type](#modifying-an-existing-type)
  - [Renaming a type's labels](#renaming-a-types-labels)
  - [Removing a type](#removing-a-type)
  - [Adding or removing a category](#adding-or-removing-a-category)
- [Validation rules](#validation-rules)
- [How the generated files are wired into the codebase](#how-the-generated-files-are-wired-into-the-codebase)
- [Telemetry — measure before you prune](#telemetry--measure-before-you-prune)
- [Limitations and known footguns](#limitations-and-known-footguns)
- [Troubleshooting](#troubleshooting)
- [Design rationale (FAQ)](#design-rationale-faq)

---

## What this is and why it exists

OpenCTEM models relationships between assets (e.g. `runs_on`, `depends_on`,
`exposes`, `monitors`) via a fixed registry of relationship types. Each
type has:

- A stable **ID** (snake_case, used in the database column and the API)
- A human-readable **direct** label (verb phrase from the source's view)
- A human-readable **inverse** label (verb phrase from the target's view)
- A **description** explaining when to use it
- A **category** for grouping in the UI dropdown
- A list of **constraints** — which `(sourceType, targetType)` combinations
  are valid

Until recently this metadata existed in **two places**:

| Location | File |
|---|---|
| Backend (Go) | `pkg/domain/asset/relationship.go` (constants + helpers) |
| Frontend (TypeScript) | `src/features/assets/types/relationship.types.ts` (union + label/constraint maps) |

The two files had to be kept in sync **by hand**. Adding `peer_of` on
the backend without updating the frontend (or vice versa) produced
silent drift: the API would accept a type the UI couldn't render, or
the UI would offer a type the API would reject. Bug bait.

The codegen workflow eliminates the drift. **The YAML file is the
single source of truth. The Go file and the TS file are generated
from it.** You edit one file, run one command, commit three.

## The 30-second mental model

```
                ┌──────────────────────────────────────┐
                │ api/configs/relationship-types.yaml  │  ← edit only this
                │      (single source of truth)        │
                └─────────────────┬────────────────────┘
                                  │
                                  │  $ make generate-relationships
                                  │
                ┌─────────────────┴────────────────────┐
                ▼                                      ▼
 api/pkg/domain/asset/                  ui/src/features/assets/types/
 relationship_types_generated.go        relationship.types.generated.ts
 (Go enum + Registry + categories)      (TS union + LABELS + CONSTRAINTS)
```

Generated files have a `// Code generated ... DO NOT EDIT.` header.
**Never edit them by hand** — the next codegen run will overwrite
your changes silently.

## Quickstart

You want to add a new type called `audited_by`. Do this:

```bash
# 1. Edit the YAML
$EDITOR api/configs/relationship-types.yaml
```

Add this entry under `types:` (anywhere, but keep it grouped with
related types):

```yaml
  - id: audited_by
    category: control_and_observability
    direct: Audited By
    inverse: Audits
    description: >-
      Compliance audit trail — asset is in scope for audit by this
      framework or auditing service.
    constraints:
      - sources: [host, database, service, cloud_account]
        targets: [service]   # auditing tool represented as service type
```

```bash
# 2. Regenerate the Go and TS files
cd api
make generate-relationships
# → ✓ Generated 19 relationship types into:
#       pkg/domain/asset/relationship_types_generated.go
#       ../ui/src/features/assets/types/relationship.types.generated.ts

# 3. Verify build is clean on both sides
GOWORK=off go build ./...
cd ../ui && npx tsc --noEmit

# 4. Commit all three files together
cd ..
git add api/configs/relationship-types.yaml \
        api/pkg/domain/asset/relationship_types_generated.go \
        ui/src/features/assets/types/relationship.types.generated.ts

git commit -m "feat(assets): add audited_by relationship type"
```

That's it. The new type is now:
- A Go constant `asset.RelTypeAuditedBy` you can use in services and
  ingest pipelines
- A TS literal `'audited_by'` in the `RelationshipType` union
- An entry in the Add Relationship dialog dropdown under
  `Control & Observability`
- Validated by the existing constraint table when users pick targets

You did not touch any code that consumes the registry — both `Go` and
`TypeScript` import from the generated file via the existing wrappers.

## File map — what lives where

```
api/
├── configs/
│   └── relationship-types.yaml              ← SOURCE OF TRUTH (edit this)
├── cmd/
│   └── gen-relationships/
│       └── main.go                          ← codegen tool
├── pkg/domain/asset/
│   ├── relationship.go                      ← Go: type + helper funcs (manual)
│   └── relationship_types_generated.go      ← Go: constants + Registry (GENERATED)
└── Makefile                                 ← contains `generate-relationships` target

ui/
└── src/features/assets/types/
    ├── relationship.types.ts                ← TS: helpers + ExtendedAssetType (manual)
    └── relationship.types.generated.ts      ← TS: union + LABELS + CONSTRAINTS (GENERATED)
```

| File | Edit by hand? | What it contains |
|---|---|---|
| `configs/relationship-types.yaml` | ✅ YES | The canonical registry — every type, label, description, constraint, category |
| `cmd/gen-relationships/main.go` | ⚠ Only if you change the codegen itself | YAML parser + Go template + TS template + validation |
| `relationship.go` | ✅ YES | `RelationshipType` typedef, `AllRelationshipTypes()`, `IsValid()`, `ParseRelationshipType()`. **Delegates to** the generated file for the actual list. |
| `relationship_types_generated.go` | ❌ NEVER | Generated. Contains `RelType*` constants, `allRelationshipTypesGenerated`, `RelationshipTypeRegistry`, `RelationshipCategories`. |
| `relationship.types.ts` | ✅ YES | `ExtendedAssetType` union, `EXTENDED_ASSET_TYPE_LABELS`, validation helper functions, `AssetRelationship` interface, graph types. **Re-exports `RelationshipType` / `RELATIONSHIP_LABELS` / `VALID_RELATIONSHIP_CONSTRAINTS` from the generated file.** |
| `relationship.types.generated.ts` | ❌ NEVER | Generated. Contains `GeneratedRelationshipType`, `GENERATED_RELATIONSHIP_LABELS`, `GENERATED_RELATIONSHIP_CONSTRAINTS`, `GENERATED_RELATIONSHIP_CATEGORIES`. |

## YAML schema reference

```yaml
# Categories used to group types in the UI dropdown.
# Display order is the order they appear here — the Add Relationship
# dialog renders them top-to-bottom.
categories:
  - id: snake_case_id          # required, unique, used by `category` field below
    name: Display Name         # required, shown as the section heading

# Relationship types.
types:
  - id: snake_case_id          # required, unique, NEVER rename without a data migration
    category: snake_case_id    # required, must match an entry in `categories`
    direct: Verb Phrase        # required, source's view ("Runs On")
    inverse: Verb Phrase       # required, target's view ("Runs")
    description: >-            # required, multi-line YAML folded — collapses to one line
      Sentence describing semantics and when to use this type.
      Shown to users in the Add Relationship dialog so they pick the
      right type. Be specific about what's IN scope and what's OUT
      (e.g. "use Foo for X, use Bar for Y").
    constraints:               # required, at least one entry
      - sources: [type1, type2]
        targets: [type3, type4]
      - sources: [type5]
        targets: [type6]
      # The full set of valid pairs for this type is the UNION of all
      # constraint tuples. Each tuple is a Cartesian product:
      # (sources × targets) is what's allowed for THAT row.
```

### Field rules

| Field | Required | Notes |
|---|---|---|
| `categories[].id` | yes | Unique. Used as a foreign key by `types[].category`. Convention: snake_case. |
| `categories[].name` | yes | Shown to users. Title Case. |
| `types[].id` | yes | Unique across the file. **Stored verbatim in the `asset_relationships.relationship_type` column** — renaming requires a data migration. Convention: snake_case verb phrase that reads naturally with `direct`. |
| `types[].category` | yes | Must match an existing `categories[].id`. |
| `types[].direct` | yes | Read aloud as: "{source} {direct} {target}". E.g. `web_app Runs On host`. |
| `types[].inverse` | yes | Read aloud as: "{target} {inverse} {source}". E.g. `host Runs web_app`. |
| `types[].description` | yes | Use YAML folded scalar (`>-`) for multi-line readability. Single trailing space and newlines are stripped at codegen time. |
| `types[].constraints[].sources` | yes | Non-empty list of `ExtendedAssetType` IDs. |
| `types[].constraints[].targets` | yes | Non-empty list of `ExtendedAssetType` IDs. |

### Naming conventions

| Type of identifier | Convention | Example |
|---|---|---|
| `types[].id` | `snake_case_verb_phrase` | `runs_on`, `sends_data_to`, `peer_of` |
| `direct` label | `Title Case Verb Phrase` | `"Runs On"`, `"Sends Data To"` |
| `inverse` label | `Title Case Verb Phrase` (passive or noun) | `"Runs"`, `"Receives Data From"` |
| `categories[].id` | `snake_case_noun_phrase` | `attack_surface_mapping` |

If your `id` is `foo_bar`, the codegen produces a Go constant
`RelTypeFooBar` (PascalCase prefix `RelType`). Don't fight this — it's
deterministic and grep-friendly.

## Workflows

### Adding a new relationship type

See the [Quickstart](#quickstart) above. The full procedure:

1. **Decide on the semantics first.** Read the existing types. Is your
   new type genuinely distinct, or is it a special case of one that
   exists? CMDB best practice favours a small registry — see
   [Design rationale](#design-rationale-faq) below.
2. **Decide on the constraints.** For each source asset type, what
   target types make sense? List them as `(sources, targets)` tuples.
3. **Edit `api/configs/relationship-types.yaml`** — add an entry under
   `types:` matching the schema above.
4. **Regenerate:**
   ```bash
   cd api && make generate-relationships
   ```
5. **Build to verify:**
   ```bash
   GOWORK=off go build ./...
   cd ../ui && npx tsc --noEmit
   ```
6. **Run the relationship tests:**
   ```bash
   cd ../api && GOWORK=off go test ./tests/unit/ -run TestAssetRelationship -count=1
   ```
   The `TestAssetRelationshipService_AllRelationshipTypes` test checks
   the count against `len(asset.AllRelationshipTypes())` — it auto-syncs
   to the registry, so you should NOT need to update the test unless
   you also want explicit per-type assertions (in which case add an
   entry to the `allTypes` slice in the test).
7. **Commit all three files together:**
   ```bash
   git add api/configs/relationship-types.yaml \
           api/pkg/domain/asset/relationship_types_generated.go \
           ui/src/features/assets/types/relationship.types.generated.ts
   ```
8. **Conventional commit message** (`feat(assets): ...`).

### Modifying an existing type

The safe operations on an existing type:

| Operation | Safety | Notes |
|---|---|---|
| Edit `description` | ✅ totally safe | Just regen + commit. |
| Edit `direct` / `inverse` labels | ✅ safe | Existing rows are unaffected; UI just shows the new label. |
| Add a constraint tuple | ✅ safe | Widens what's pickable. |
| Remove a constraint tuple | ⚠ careful | New edges of the removed combination can no longer be created. **Existing rows in the DB stay valid** (no migration). Make sure no ingest pipelines rely on the removed combination. |
| Change `category` | ✅ safe (UI-only) | Type moves to a different dropdown section. |
| **Rename `id`** | 💣 BREAKS DATA | The ID is stored verbatim in `asset_relationships.relationship_type`. Renaming requires a backfill migration. **Don't do this without a plan.** |

For everything except the ID rename, the workflow is the same as
adding a type: edit YAML → `make generate-relationships` → build →
commit.

### Renaming a type's labels

Cosmetic only. Edit `direct` / `inverse` in the YAML, regen, commit.
Existing rows are unaffected because labels are derived from the
registry at render time, not stored in the DB.

```yaml
- id: monitors
  direct: Monitors             # change this...
  inverse: Monitored By        # ...and/or this
  # ↓ description stays
```

Don't rename the `id` — that's a data-breaking change (see below).

### Removing a type

Removing a type from the YAML is a **breaking change** because:

1. **Existing DB rows** with that type become orphans — they exist but
   the UI can't render them and the backend can't accept new ones.
2. **Code references** to the deleted constant (e.g.
   `asset.RelTypeFoo`) will fail to compile.
3. **Ingest pipelines** that create the type will break.

The safe procedure:

1. **Find every reference** to the constant in the Go codebase:
   ```bash
   cd api
   grep -rn "RelTypeFoo" --include="*.go" .
   ```
2. **Find every reference** to the type ID in the TS codebase:
   ```bash
   cd ../ui
   grep -rn "'foo'" src --include="*.ts" --include="*.tsx" \
     | grep -v "lib/clipboard.ts"   # exclude noise
   ```
3. **Replace the references** with whatever the new canonical type is
   (or delete the code paths that needed them).
4. **Write a backfill migration** to handle existing rows. Two options:
   - **Convert** them to a different type. Example: when `member_of`
     was removed in favour of `contains`, the migration was
     `UPDATE asset_relationships SET relationship_type='contains',
     source_asset_id=target_asset_id, target_asset_id=source_asset_id
     WHERE relationship_type='member_of';` (also reversed the source/target
     direction).
   - **Delete** them. Use this when no equivalent type exists.
5. **Edit the YAML** — remove the type entry. Regenerate.
6. **Build to verify** Go and TS both compile.
7. **Test the migration** on a copy of production before applying.

For the most recent removal, see migration
`migrations/000107_relationship_deployed_to_backfill.up.sql` for the
template — it documents the inspection query, the conversion logic,
and the no-op down migration.

### Adding or removing a category

Categories are display-only — they don't affect data. The procedure:

1. **Add a new category** by appending to `categories:` in the YAML
   (display order is the order in the file).
2. **Update each `types[].category`** field if you want existing types
   to move into the new section.
3. Regenerate, build, commit.

**Removing a category** requires that no `types[].category` references
it. The codegen will fail with `type "X" references unknown category
"Y"` if you remove a category that's still in use.

## Validation rules

The codegen tool runs these checks before writing any files. If any
fail, the tool exits with a non-zero status and the existing generated
files are left untouched.

| Rule | Error message |
|---|---|
| `categories` is non-empty | `no categories defined` |
| `types` is non-empty | `no types defined` |
| Every category has both `id` and `name` | `category with empty id or name` |
| Category IDs are unique | `duplicate category id "X"` |
| Every type has a non-empty `id` | `type with empty id` |
| Type IDs are unique | `duplicate type id "X"` |
| Every type's `category` exists in `categories` | `type "X" references unknown category "Y"` |
| Every type has both `direct` and `inverse` labels | `type "X" has empty direct or inverse label` |
| Every type has at least one constraint | `type "X" has no constraints` |
| Every constraint has both non-empty `sources` and `targets` | `type "X" constraint #N has empty sources or targets` |

The validation runs in `cmd/gen-relationships/main.go:validate()`.

> **Asset type IDs are NOT validated.** You can put a typo like
> `webiste` in a constraint and the codegen will accept it. The
> backend will silently never match anything; the frontend dropdown
> will show no options. See [Limitations](#limitations-and-known-footguns)
> below.

## How the generated files are wired into the codebase

### Go side

`pkg/domain/asset/relationship.go` (manual file) provides the public
API used by services and handlers:

```go
type RelationshipType string

func AllRelationshipTypes() []RelationshipType {
    out := make([]RelationshipType, len(allRelationshipTypesGenerated))
    copy(out, allRelationshipTypesGenerated)
    return out
}

func (t RelationshipType) IsValid() bool {
    return slices.Contains(AllRelationshipTypes(), t)
}

func ParseRelationshipType(s string) (RelationshipType, error) { /* ... */ }
```

`pkg/domain/asset/relationship_types_generated.go` (generated)
provides the underlying data:

```go
const (
    RelTypeRunsOn       RelationshipType = "runs_on"
    RelTypeDeployedTo   RelationshipType = "deployed_to"
    // ... 16 more
)

var allRelationshipTypesGenerated = []RelationshipType{ /* in YAML order */ }

var RelationshipTypeRegistry = map[RelationshipType]RelationshipTypeMetadata{
    RelTypeRunsOn: {
        ID:          RelTypeRunsOn,
        Category:    "attack_surface_mapping",
        Direct:      "Runs On",
        Inverse:     "Runs",
        Description: "Runtime location of a workload — ...",
        Constraints: []RelationshipConstraint{
            {Sources: []string{"service", "api", "website"}, Targets: []string{"host", "container", ...}},
            // ...
        },
    },
    // ...
}

var RelationshipCategories = []RelationshipCategory{
    {ID: "attack_surface_mapping", Name: "Attack Surface Mapping"},
    // ...
}
```

To use a relationship type from a Go service:

```go
import "github.com/openctemio/api/pkg/domain/asset"

// Reference a constant
asset.RelTypeRunsOn

// Read its metadata
meta := asset.RelationshipTypeRegistry[asset.RelTypeRunsOn]
fmt.Println(meta.Direct)        // "Runs On"
fmt.Println(meta.Description)   // full sentence

// Iterate every type
for _, t := range asset.AllRelationshipTypes() { /* ... */ }
```

### TypeScript side

`src/features/assets/types/relationship.types.ts` (manual file)
re-exports the generated symbols under the names the rest of the UI
already imports:

```ts
import {
  type GeneratedRelationshipType,
  GENERATED_RELATIONSHIP_LABELS,
  GENERATED_RELATIONSHIP_CONSTRAINTS,
  ALL_GENERATED_RELATIONSHIP_TYPES,
} from './relationship.types.generated'

export type RelationshipType = GeneratedRelationshipType

export const RELATIONSHIP_LABELS: Record<RelationshipType, RelationshipLabelPair> =
  GENERATED_RELATIONSHIP_LABELS

export const VALID_RELATIONSHIP_CONSTRAINTS: Record<
  RelationshipType,
  RelationshipConstraint[]
> = GENERATED_RELATIONSHIP_CONSTRAINTS as Record<RelationshipType, RelationshipConstraint[]>

export const ALL_RELATIONSHIP_TYPES: RelationshipType[] = ALL_GENERATED_RELATIONSHIP_TYPES
```

The validation helper functions (`isValidRelationship`,
`getValidTargetTypes`, `getValidRelationshipTypes`, `getInverseLabel`,
`getDirectLabel`) live in this file too. They consume
`VALID_RELATIONSHIP_CONSTRAINTS` and `RELATIONSHIP_LABELS`, so they
automatically pick up new types from the codegen with no changes.

To use a relationship type from a React component:

```ts
import {
  type RelationshipType,
  RELATIONSHIP_LABELS,
  isValidRelationship,
  getValidRelationshipTypes,
} from '@/features/assets/types'

// All types valid for a given source asset type
const types = getValidRelationshipTypes('database')

// Get the label for a type
const { direct, inverse, description } = RELATIONSHIP_LABELS['runs_on']

// Validate a (source, type, target) triple
const ok = isValidRelationship('runs_on', 'service', 'host')
```

The Add Relationship dialog uses
`GENERATED_RELATIONSHIP_CATEGORIES` directly to render the dropdown
grouped by category — see
`src/features/assets/components/relationships/add-relationship-dialog.tsx`.

## Telemetry — measure before you prune

A frequent question is "should we delete this type, nobody uses it."
The honest answer is "you don't know — go count first." There's a
backend endpoint for that:

```
GET /api/v1/relationships/usage-stats
Authorization: Bearer <jwt>
```

Returns one entry per relationship type registered, with that tenant's
count of relationships of that type. **Zero-count entries are
included** — they're the candidates for removal:

```json
{
  "data": [
    {
      "id": "runs_on",
      "direct": "Runs On",
      "inverse": "Runs",
      "description": "Runtime location of a workload — ...",
      "category": "attack_surface_mapping",
      "count": 1247
    },
    {
      "id": "audited_by",
      "direct": "Audited By",
      "inverse": "Audits",
      "description": "...",
      "category": "control_and_observability",
      "count": 0
    }
  ],
  "total": 19
}
```

**Recommended workflow**: run this monthly. Types with count=0 after
3 consecutive months are strong candidates for removal. Types you
*want* but don't see in the list are candidates for adding.

This is the only honest way to converge on a registry tuned to YOUR
data instead of theoretical CMDB best practice.

The implementation lives in
`internal/app/asset_relationship_service.go:GetRelationshipTypeUsage`
and `internal/infra/postgres/asset_relationship_repository.go:CountByType`.

## Limitations and known footguns

### Asset type IDs are not validated

The constraint table references asset types by string:

```yaml
constraints:
  - sources: [service, api, website]
    targets: [host, container, k8s_workload, cloud_account]
```

A typo here — `webiste` instead of `website` — will pass codegen
validation, compile cleanly on both Go and TS, and silently never
match anything in production. The picker dropdown will show no valid
targets when the user picks the type.

**Mitigation**: when adding a type, manually verify each source/target
ID against the `ExtendedAssetType` union in
`ui/src/features/assets/types/relationship.types.ts`. A future codegen
improvement could load the asset type list from the Go side and
cross-validate; for now this is a manual responsibility.

### Some "asset types" don't exist on the backend

The constraint table uses several asset type IDs that exist only on
the frontend (`k8s_cluster`, `k8s_workload`, `container_image`,
`api_collection`, `api_endpoint`, `identity_provider`, `compute`).
They're "virtual" types — not real `AssetType` enum values in Go.

Consequence: **the backend cannot enforce the constraint table** for
those types. The frontend filter is advisory only. The only
server-side rule we enforce is the `runs_on`/`deployed_to` placement
mutex (in `internal/app/asset_relationship_service.go`).

**Long-term fix**: either add those types as real `AssetType` enum
values in the backend, or add an alias map in the YAML/codegen that
resolves virtual types to base types. Tracked as a TODO in the YAML
header comment.

### `AssetRelationshipService_AllRelationshipTypes` test is partially auto-syncing

The test in `tests/unit/asset_relationship_service_test.go` has two
parts:
1. A hard-coded `allTypes` slice listing every type by string ID
2. A `len(allTypes) == len(asset.AllRelationshipTypes())` assertion

Part 2 auto-syncs to the registry. **Part 1 does NOT** — if you add a
new type, the test still passes (because the assertion uses
`AllRelationshipTypes`), but the explicit per-type test cases don't
cover the new type. Add an entry to `allTypes` for full coverage.

### Generated files are committed to the repo

We commit `relationship_types_generated.go` and
`relationship.types.generated.ts` rather than generating at build
time. Reasons:
- CI doesn't need a YAML parser
- Code review sees the diff cleanly
- Drift between the YAML and the generated files is impossible to
  introduce silently — git tells you about it

**Cost**: you have to remember to run `make generate-relationships`
after editing the YAML, and commit all three files. If you commit
the YAML alone, CI will pass (because the old generated files still
exist and are still valid Go/TS), but production code won't reflect
your YAML change. **Always run the codegen and commit all three.**

## Troubleshooting

### `make generate-relationships` errors with `validate config: ...`

The codegen's validator caught a problem in your YAML. Common cases:

| Error | Fix |
|---|---|
| `duplicate type id "X"` | You have two entries with the same `id`. |
| `type "X" references unknown category "Y"` | Either fix the typo in `category:` or add `Y` under `categories:`. |
| `type "X" has empty direct or inverse label` | Add the missing label. |
| `type "X" has no constraints` | Add at least one `(sources, targets)` tuple. |
| `type "X" constraint #N has empty sources or targets` | The Nth tuple has an empty list. Either remove the tuple or fill it in. |

### `go build ./...` fails with `undefined: asset.RelTypeFoo`

You removed a type from the YAML but other Go code still references
the old constant. Search for it:

```bash
grep -rn "RelTypeFoo" --include="*.go" .
```

Update or delete the references, then rebuild.

### `npx tsc --noEmit` fails with `Type '"foo"' is not assignable to type 'ExtendedAssetType'`

You used an asset type ID in a constraint that doesn't exist in the
`ExtendedAssetType` TS union. Check the spelling against
`src/features/assets/types/relationship.types.ts:ExtendedAssetType`.
Either fix the typo or add the missing type to the union.

### The Add Relationship dropdown doesn't show my new type

Make sure you ran `make generate-relationships` AND restarted the
Next.js dev server. Hot reload usually picks up the change but
occasionally needs a restart for new module exports.

If the type appears in the dropdown but the picker is empty no matter
what you search, the constraint's `sources` or `targets` probably
reference asset type IDs that don't exist (see "Asset type IDs are
not validated" above).

### CI says "uncommitted generated files"

You edited the YAML, committed only the YAML, and a CI check (or your
own pre-push hook) noticed the generated files are stale relative to
the YAML. Run `make generate-relationships` and commit the two new
generated files in a follow-up commit (or amend, if local).

## Design rationale (FAQ)

### Why YAML and not JSON / TOML / a Go-defined config?

- **YAML** has folded multi-line strings (`>-`) which makes the
  `description` fields readable inline.
- **JSON** has no comments and no multi-line strings. Reviewing a 500-
  line JSON file is painful.
- **TOML** is fine but the team is already familiar with YAML from
  the seed/config files.
- **Go-defined config** (a `.go` file with map literals) was the
  original state and the reason we built the codegen. The problem is
  it can't drive the TS side — every change needs a parallel TS edit.

The YAML is a small file (~280 lines) and the schema is fixed and
documented. It's the right choice.

### Why generate AOT (commit the files) instead of at runtime?

See [Limitations → Generated files are committed to the repo](#limitations-and-known-footguns).
Short version: code review, CI simplicity, and grep-friendly drift
detection.

### Why is the registry global instead of per-tenant?

CMDB best practice strongly favours a small, fixed registry shared by
all tenants. Tenant-customizable type registries produce data that
can't be joined across tenants, break analytics, and inevitably lead
to one tenant having dozens of types nobody else recognizes.

The current registry IS small (18 types) and matches common CTEM
patterns. If a particular tenant has a domain-specific concept (e.g.
"settles_with" for a clearing house), the right answer is to add it
to the global registry so OTHER tenants in the same vertical can
benefit too — not to make it tenant-private.

When adding a type that feels narrow, ask: "Would another tenant in
this customer's industry plausibly want this?" If yes → add it
globally. If no → it's probably a metadata field on the existing
relationship (`tags`, `description`, custom JSONB), not a new type.

### Why are some types missing that other CMDBs have (like `member_of`)?

`member_of` is the inverse of `contains`. Having both produces
inconsistent data: some users model `host contains container`, others
model `container member_of host`. We picked one canonical direction
(`contains`, source = parent, target = child) and removed the
inverse. See the YAML header comment for the rule.

Similarly `owned_by` was removed because asset ownership lives in the
proper `asset_owners` table (with primary/secondary/stakeholder/etc.
via the RACI model) — having a relationship type for it would have
created two data paths for the same concept.

### How do I know if my new type is actually being used?

Use the [usage-stats endpoint](#telemetry--measure-before-you-prune).
If a type sits at count=0 for several months, it probably isn't
solving a real problem. Remove it and free up dropdown space.

### Why does adding a type require touching three files?

You don't touch three files — you touch ONE file (the YAML). The
other two are generated. The reason we commit the generated outputs
to git (rather than running the codegen at build time) is so:

- Code review sees the actual change at the consumer level
- CI doesn't need a Go runtime
- Stale generated files vs YAML are detectable via git status

Conceptually it's a one-file change. Practically it's three files in
the commit.

---

## Cheat sheet

```bash
# Add / modify / remove a type
$EDITOR api/configs/relationship-types.yaml
cd api && make generate-relationships
GOWORK=off go build ./...
cd ../ui && npx tsc --noEmit
git add api/configs/relationship-types.yaml \
        api/pkg/domain/asset/relationship_types_generated.go \
        ui/src/features/assets/types/relationship.types.generated.ts
git commit -m "feat(assets): <conventional message>"

# See what types are actually used
curl -H "Authorization: Bearer $JWT" \
     https://your-tenant/api/v1/relationships/usage-stats | jq '.data[] | select(.count == 0)'

# Run relationship tests
cd api && GOWORK=off go test ./tests/unit/ -run TestAssetRelationship -count=1

# Find references to a constant before removing it
grep -rn "RelTypeFoo" --include="*.go" .
grep -rn "'foo'" ui/src --include="*.ts" --include="*.tsx"
```
