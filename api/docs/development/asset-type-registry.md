# Asset type registry

`api/configs/asset-types.yaml` is the one definition of the asset types,
their classes and the lenses those classes belong to. It implements RFC-042
§6.3 and slice 1 of §9.1 (`docs/rfcs/RFC-042-asset-inventory-v2.md`).

## What it declares

| Level | Count | Where |
|---|---|---|
| Lens (inventory tab) | 8 | `lenses:` |
| Class (JupiterOne `_class`) | 16 + `other` | `classes:`; each class has one lens, `other` has none |
| Type | 37 + `unclassified` | `types:`; each type has one class |

Each type entry declares:

- `class` (the lens follows from the class);
- `alias_of`, for an input name that is stored as (core type, sub_type),
  optionally with a `provider` and `attributes` (`s3_bucket` is stored as
  `(storage, bucket)` + provider `aws`). Aliases are never stored. An alias
  keeps its own class: a `host` with sub_type `serverless` is a `function`.
  Its sub_type must be in the core type's `sub_types`; it may be left out
  only when the alias has the core type's class (`data_store`);
- `sub_types`, the closed list of kinds of a core type. A sub-type is a
  kind, never a vendor or an engine;
- `sub_type_inputs`, legacy sub-type values still accepted on input and what
  they are stored as: `{ type, sub_type, provider, attributes }`
  (`postgresql: { sub_type: relational, attributes: { engine: postgresql } }`).
  Provider and attributes are set only where the asset has no value;
- typed `attributes` (string, int, number, bool, time, enum, list, object).
  `facet: true` / `group: true` make an attribute a facet or group-by field,
  named `<type>.<attribute>`;
- `columns` (core fields or attributes), the `card` renderer and the detail
  `sections`, from closed sets the web implements;
- `identity_keys` in match order: RFC-028 identifier kinds, `attr.<name>`,
  and always `name` last;
- `legacy_category`, the value of the old `category` field of asset
  responses;
- `scannable_by`, the tool target types (a tool's `supported_targets`:
  `url`, `domain`, `ip`, `host` …) that can scan the type. An alias without
  a list uses its core type's; with one, it is the list of that
  (core type, sub_type);
- `exposure_default`, the exposure a type has by nature (`public` for
  domains, certificates and web applications). Ingest applies it when the
  scanner sent no exposure.

## Reading the registry in feature code

Feature code never compares an asset's type with a type name. It asks the
registry about the stored (type, sub_type) pair
(`pkg/domain/asset/type_behaviour.go`):

| Question | Function |
|---|---|
| The pair a row stands for (a legacy alias row reads as its alias's pair) | `CanonicalPair` |
| Default exposure | `DefaultExposure` |
| Tool target types that can scan it | `ScannableBy` |
| Is a relationship allowed (human writes are refused otherwise) | `RelationshipAllowed`, `AllowedRelationshipTargets` |
| Does a name a person wrote in a rule cover it (`website`, `firewall`) | `TypeNameMatches` |
| A type filter that must still find legacy alias rows | `WithLegacyNames` |

The web does the same through `web/src/features/asset-types/type-match.ts`.
`alias_constants_lint_test.go` fails the build when non-test Go code outside
the resolver names an alias constant (`AssetTypeWebsite` …): such a
comparison silently never matches a stored row.

Allowed relationships are not written per type. The generator resolves the
constraints of `configs/relationship-types.yaml` to real types, using the
`virtual_types` table for the frontend names (`k8s_workload`,
`container_image` …), and fails on any name it cannot resolve. A virtual
name for a concept without a type yet is marked `unmodelled: true`
(`credential`, a secret) and its constraints are skipped.

## Input types and stored types

Every write path resolves its input with `asset.ResolveInputType` (people
and API clients: REST, CSV and bulk import) or `asset.ResolveInputTypeLenient`
(ingest, sensors, connectors):

| Input | Stored | REST / import | Ingest |
|---|---|---|---|
| core type, declared sub-type | as given | accepted | accepted |
| alias (`website`) | `(application, website)` | accepted | accepted |
| legacy sub-type (`database` + `postgresql`) | `(database, relational)` + `engine` | accepted | accepted |
| alias + a different sub-type (`website` + `api`) | — | 400 | alias kept, sub-type in `x_native_sub_type` |
| undeclared sub-type (`network` + `lan`) | — | 400 | no sub-type, value in `x_native_sub_type` |
| unknown type | — | 400 | `unclassified` |

`asset.NewAssetWithSubType` refuses anything else, so a writer that skips
the resolver fails loudly. `PATCH /assets/{id}` accepts `sub_type` (the type
of an existing asset cannot change) and records a `reclassified` state
history entry.

## What is generated

| Output | Contents |
|---|---|
| `pkg/domain/asset/registry_generated.go` | the registry data, `Class`/`Lens`/`Category` constants, `TypeAliases`, the stored types and the input map |
| `web/src/features/asset-types/registry.generated.ts` | the closed sets and labels, `STORED_ASSET_TYPES`, `ASSET_SUB_TYPES`, `ASSET_TYPE_ALIASES` |
| `make asset-types-sql` (printed) | the `asset_types` seed (with `sub_types` and `is_storable`), the `asset_type_input_map` rows and the `assets` re-backfill, for a migration |

`GET /api/v1/asset-types` serves `asset.RegistryDocument()` with a strong
ETag. Its `data`/`total`/`page` fields are the legacy `asset_types` rows and
are deprecated. The web reads the registry through `useAssetTypeRegistry()`.

In the database, `asset_types.class`, `lens`, `alias_of` and
`alias_sub_type` hold the seed. The trigger `trg_assets_registry_class`
derives `assets.asset_class` and `assets.asset_lens` from
(`asset_type`, `sub_type`) on every insert and update. A direct write to
those two columns is re-derived, so they never disagree with the type.

## Rules for registry changes

RFC-042 §6.3.8 (type model hardening, accepted 2026-10-03) adds these
rules. A registry PR that breaks one needs an RFC amendment first.

1. **Aliases are input names only.** An `alias_of` entry is resolved to
   (core type, sub_type) on every write path and is never stored. Code
   outside the registry and the ingest mapper never compares against an
   alias name: key on the class or on (core type, sub_type).
2. **A sub-type is a kind**, from the core type's closed `sub_types`
   list. Vendors go to `provider`, engines and operating systems to an
   attribute. A legacy value that is still accepted on input is mapped
   explicitly, never left as free text.
3. **Every class has a core type of its own**, and an alias resolves
   within its own class.
4. **No type without a producer.** Add a type or sub-type only together
   with the parser, connector or committed RFC that produces it.
5. **Behaviour is declared here**, not coded: which tool target types can
   scan the type, its default exposure, its relationship constraints.
6. **This file is the only list of types.** Do not add a hand-written
   type list in Go, TypeScript or SQL; generate it or read the registry.

## Changing the registry

1. Edit `configs/asset-types.yaml`.
2. Run `make generate-asset-types`.
3. If a class, lens or alias changed, add a migration whose body is the
   output of `make asset-types-sql`. It re-seeds `asset_types` and calls
   `asset_registry_backfill` to re-derive existing assets in batches. Never
   edit an applied migration.
4. Commit the YAML, the generated files and the migration together.

## Drift checks

- **CI step "Asset Types Drift"** (`make asset-types-check`): fails when the
  generated Go or TS file, or the registry block of the newest migration that
  has one, differs from the YAML.
- **`cmd/gen-asset-types` tests:** the same check as a unit test, and the
  validation rules.
- **`pkg/domain/asset` registry tests:** every type has a class, a lens
  (except `unclassified`) and valid identity keys. `TypeAliases` and the
  legacy categories are unchanged.
- **`internal/infra/postgres` `TestAssetTypeRegistry_*`** (with
  `DATABASE_URL`): the `asset_types` rows and CHECK constraints match the
  registry, the trigger agrees with `asset.ClassOf` for every stored pair, and
  the backfill repairs stale rows.
