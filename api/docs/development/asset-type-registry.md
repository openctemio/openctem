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
- `alias_of`, for a legacy type that ingest stores as (core type, sub_type).
  An alias keeps its own class: a `host` with sub_type `serverless` is a
  `function`;
- typed `attributes` (string, int, number, bool, time, enum, list, object).
  `facet: true` / `group: true` make an attribute a facet or group-by field,
  named `<type>.<attribute>`;
- `columns` (core fields or attributes), the `card` renderer and the detail
  `sections`, from closed sets the web implements;
- `identity_keys` in match order: RFC-028 identifier kinds, `attr.<name>`,
  and always `name` last;
- `legacy_category`, the value of the old `category` field of asset
  responses.

Allowed relationships are not written per type. The generator resolves the
constraints of `configs/relationship-types.yaml` to real types, using the
`virtual_types` table for the frontend names (`k8s_workload`,
`container_image` …), and fails on any name it cannot resolve.

## What is generated

| Output | Contents |
|---|---|
| `pkg/domain/asset/registry_generated.go` | the registry data, `Class`/`Lens`/`Category` constants, `TypeAliases` |
| `web/src/features/asset-types/registry.generated.ts` | the closed sets and labels |
| `make asset-types-sql` (printed) | the `asset_types` seed and the `assets` re-backfill, for a migration |

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
