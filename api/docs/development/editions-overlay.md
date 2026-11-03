# Editions: overlay code organization, compatibility and upgrades

Companion to [editions.md](editions.md) (where paid-feature code goes and the
edition fence). This page fixes how the private overlay plugs into the core, how
it keeps working across core releases, and how an installation moves between the
Community and Enterprise editions.

## Dependency rule

```
overlay ──► extension contract   api/internal/extension (Go), web/src/lib/extension/types.ts (web)
        ──► public packages      api/pkg/..., web shared UI          (best effort)
core    ──X never imports the overlay
```

- Only `api/cmd/server/edition_ee.go` (build tag `ee`) imports the overlay
  package, and only the `@ee/*` web modules resolve to it. The edition fence
  enforces both.
- The overlay uses the extension contract, the types the contract names
  (`internal/infra/postgres`, `internal/config`, `internal/infra/controller`)
  and public `api/pkg/...` packages. Everything else in `internal/` is off limits;
  when the overlay needs core behaviour, the core adds a seam (below).
- A seam is generic and brand-neutral, has a Community default that keeps
  today's behaviour, and is tested in this repository with a fake overlay.

## The contract and its version

| Contract | Version constant | Tests in this repository |
|---|---|---|
| `api/internal/extension`: `Edition` (one registration, one optional field per seam), `Deps`, `Runner` | `extension.APIVersion` | `internal/extension` tests with a fake `Edition` |
| `web/src/lib/extension/types.ts`: `WebExtension`, `ConsoleExtension`, `ExtensionMessages`, slot ids | `EXTENSION_API_VERSION` | `src/lib/extension/__tests__` (default build adds nothing; a mocked overlay reaches sidebar, settings and slots) |

- The overlay states the version it was written for as a literal. A mismatch
  stops registration (Go) or module load (web), so the overlay's CI and any
  start fail loudly.
- Adding an optional field or a slot is not a break. Removing, renaming or
  narrowing one is: bump the version.
- Change a seam in three steps: add the new one beside the old (no bump), let the
  overlay move to it, then remove the old one and bump. Never in one pull request.
- A pull request touching a contract path updates the contract tests and this
  page; CODEOWNERS requires the maintainer.

## Extension points, one per kind

| Kind | Mechanism |
|---|---|
| Grants (things off unless granted) | `Edition.Grants` → `limits.GrantProvider`; gates call `entitlement.Service.RequireAddon` |
| Background jobs | `Edition.Controllers`, run by the core controller manager |
| HTTP routes | an `Edition` route registration in which every route names a permission and a grant key; the core mounts it behind its tenant, permission and grant middleware (added with the first route that moves) |
| Behaviour inside core flows | one typed `Edition` field per seam with a Community default (branding source, trust policy, simulation link, member lifecycle, tenant-data duties) |
| Settings | extension-only environment keys are listed in `cmd/server/edition_guard.go`: a Community server refuses to start with one set |
| Migrations | the overlay's own set in schema `ee`, applied after the core set ([editions.md](editions.md#overlay-migrations)) |
| Web navigation | `@ee/web` `navItems` (by sidebar group title) and `settingsItems` (by settings group id), merged into `config/sidebar-data.ts` and `config/settings-nav.ts`; gated by `module`/`permission` like core rows |
| Web pages | route groups `src/app/(dashboard)/(ee)/` (inside the core shell) or `src/app/(ee)/`; the URL does not change when a page moves |
| Places in core pages | `<ExtensionSlot id="..." />`; ids and props in `types.ts` (`ExtensionSlotProps`) |
| Replacing a core component | only the short allowlist in `ExtensionOverrideProps` (today `auth.footer`), each with a stable props contract: `<Overridable id="..." fallback={CoreComponent} />` |
| Strings | `@ee/messages` `{ en, vi }` merged into the catalogs; adding keys only, a core key cannot be replaced |
| Console | `@ee/console` `navItems` (by section `i18nKey`); pages in `console/src/app/(console)/(ee)/` |

Core pages are never copied into the overlay. A missing customisation point is a
core pull request adding a generic slot (or, rarely, an override id) with a test;
look and feel changes go through design tokens and brand settings, never by
replacing a component for its styling.

The aliases are set in `web/next.config.ts` and `web/console/next.config.ts`
(`EDITION=ee` selects the overlay, otherwise `src/ee-stub`), in `vitest.config.ts`
(always the stub), and typed by `src/lib/extension/ee-modules.d.ts`. A default
production build refuses to run while an overlay is mounted, and an `EDITION=ee`
build without one fails to resolve.

## Overlay layout

The overlay repository uses the core's paths, so mounting is one copy per mount
point and a path means the same in both trees: `api/ee/register.go` (the only
wiring file), one directory per feature under `api/ee/` and `web/src/ee/`, the
`ee` migration set under `api/ee/migrations/`, pages in the `(ee)` route groups.
Every mount point is git-ignored here.

## Testing and CI

- **This repository, every pull request:** the edition fence; the contract tests
  above; Community behaviour tests for every seam.
- **The overlay's CI:** its tests and the core's extension tests with `-tags ee`,
  the combined build, migrations core → `ee` up → down → up, cross-tenant
  negatives for every Enterprise route, the upgrade test below; on every overlay
  pull request (against its pinned core commit), hourly against `develop`, and on
  each release tag.
- **No private code in public CI.** Workflows in this repository never check out
  or receive credentials for the overlay: their logs are public and branch pull
  requests run their own workflow files. The overlay watches this repository
  instead.

## Versions and releases

- The overlay pins one core commit and moves it forward after its drift job is
  green against `develop`.
- One core tag `vX.Y.Z` builds the Community images here and, in the overlay's
  release job, the Enterprise images from the same commit. The Enterprise images
  for a tag exist only once the overlay suite passes on that tag; Community
  releases never wait for them.
- `/version` reports the edition.

## Moving an installation between editions

Same database, data, configuration and keys; only the images change.

| From | To | Supported |
|---|---|---|
| Community vX | Enterprise vX | always |
| Community vX | Enterprise vY (Y > X) | along the normal upgrade path for X → Y |
| Enterprise vX | Enterprise vY | core migrations, then the `ee` set |
| Enterprise vX | Community vX | yes: schema `ee` stays, unused, and nothing is lost |
| Enterprise vY | Community vX (X < Y) | no: restore the pre-upgrade backup, as for any downgrade |

Guarantees the core keeps:

- Nothing in the core reads, writes or drops schema `ee`; a Community server and
  its migrations run unchanged on a database that has one.
- Users, sessions, sensors (no re-pairing), API keys, SSO settings,
  `APP_ENCRYPTION_KEY` and the fingerprint key are untouched by a swap.
- Without a licence an Enterprise image behaves exactly like Community, so the
  images can be swapped first and the licence activated afterwards.
- A setting that only an extension understands stops a Community server with a
  clear message, so moving back never drops a feature silently.

Known limits: key rotation (`internal/app/rekey`) re-encrypts the current schema
only, so overlay tables keep no data encrypted with the application key until a
rekey seam exists; overlay table names never repeat a core table name.

Procedure: back up (the backup dumps every schema), rehearse on a restored copy,
switch the images (compose image names, Helm `edition` and registry values, the
Ansible kit variable), start (migrations: core set, then `ee`), activate the
licence, verify, and switch back to roll back.

## Adding a paid feature or moving one

1. Decide the tier; register the grant key (overlay).
2. Here: the seam with a Community default, a fake-overlay contract test, a
   Community-unchanged test, a row in [editions.md](editions.md); for a move, the
   feature leaves the Community build and its tables stay; extension-only
   settings go to `edition_guard.go`. Bump the contract version only for a break.
3. Overlay: the feature, its registration, routes with permission and grant key,
   tenant-scoped queries, `ee` migrations with `tenant_id` cascading to
   `public.tenants`, tenant-data duties, tests (unlicensed, expired, cross-tenant,
   out-of-scope), web under `web/src/ee/`, the pinned core commit moved to the
   seam's merge commit.
4. Docs: the docs-site Enterprise badge and upgrade notes.
