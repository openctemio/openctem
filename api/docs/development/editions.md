# Editions: where paid-feature code goes

This repository is the open core and the only place product code is written.
A private overlay repository holds the paid (Enterprise) features only; a
release builds the Community images from this tree and the Enterprise images
from the same tree plus the overlay. The Community build must never contain
Enterprise code.

**Rule: paid-feature code is written only in the private overlay repository.
The core gets extension points and entitlement keys only.** Never push overlay
code here, not even to a branch.

## What lands here for a paid feature

1. An entitlement key, registered in [`pkg/domain/limits`](../../pkg/domain/limits/registry.go)
   with a description. `tests/unit/entitlement_keys_test.go` fails on a key
   without one, on a key built from a string literal, and on an unknown key.
2. A generic extension point (an interface with a Community default that does
   nothing), consulted through the entitlement service
   ([limits and feature denies](../architecture/limits.md)). Checking a plan,
   tier or edition by name is refused by the same test file.
3. Tests that Community behaviour is unchanged.

## Extension-point locations (maintainer review via CODEOWNERS)

| Path | Role |
|---|---|
| `api/internal/extension/` | the registration point: the overlay registers its edition and the seams it fills (grants today; routes, permissions and settings as they are needed) |
| `api/cmd/server/edition_*.go` | the build switch: `edition_ee.go` carries the `ee` build tag and is the only file that may |
| `api/pkg/domain/limits/` | entitlement keys and their descriptions |
| `api/ee/`, `web/src/ee/`, `web/src/app/(ee)/`, `web/console/src/ee/`, `web/console/src/app/(ee)/` | overlay mount points: git-ignored, empty in this repository |
| `web/src/ee-stub/` | what the `@ee` alias resolves to in the default build |

The `ee-stub` directory is created with the first web extension point; the
CODEOWNERS entries exist already.

## How an overlay plugs in

- **Build switch.** `api/cmd/server/edition_ee.go` (build tag `ee`) is the only
  file that imports the overlay package `api/ee`. `api/ee/doc.go` keeps that
  package present and empty in this repository, so `go build -tags ee`,
  `go mod tidy` and editors work without the overlay. The overlay's `init`
  calls `extension.Register` once.
- **Registration** ([`internal/extension`](../../internal/extension/extension.go)).
  The overlay registers one `Edition`: a name and constructors for the seams it
  fills. The core hands it `extension.Deps` (the database pool and the logger)
  and nothing else. A second registration panics at start; a constructor that
  fails is logged and the core runs with its defaults, so an overlay can never
  stop the server or switch off a Community feature.
- **Grants** (things that are off unless granted). The core defines only the
  shape of the answer in [`pkg/domain/limits/grants.go`](../../pkg/domain/limits/grants.go):
  `GrantKey`, `GrantStatus`, `Grant`, `Notice` and the `GrantProvider`
  interface. Every gate asks `entitlement.Service.Addon` / `RequireAddon`
  (403 `ADDON_NOT_LICENSED` or `ADDON_LICENSE_EXPIRED`, fail-closed for grants
  only) and banners read `entitlement.Service.Notices`. The Community build has
  no provider: every grant is `none` and there are no notices. The grant keys
  themselves, the licence verifier, licence storage and the console page that
  manages a licence all live in the overlay; this repository holds no licence
  parsing, no keys and no licence table
  ([RFC-145](../rfcs/RFC-145-enterprise-licence-and-entitlements.md)).
- **A provider that keeps itself fresh** implements `extension.Runner`; the
  server runs it in the background on every plane until shutdown.

## Overlay migrations

The overlay keeps its tables in its own Postgres schema, `ee`, and applies them
with the same `openctem-migrate` tool, connected with `search_path=ee`. The
tool keeps its tracking tables in the connection's current schema, so the
overlay set is tracked in `ee.schema_migrations` (with its own migration lock)
and never mixes with the core set in `public`. Rules:

- Overlay migrations create objects only in schema `ee` and name core tables
  with their schema (`public.tenants`). Core migrations never reference `ee`.
- The schema is created before the tool runs. If it is missing, the current
  schema is empty and the tool refuses to run, so a mistake can never write
  overlay versions into the core's tracking tables.
- Organization data in an overlay table carries `tenant_id` with a foreign key
  `ON DELETE CASCADE` to `public.tenants`, like core tables.
- Going back to a Community image leaves schema `ee` unused; nothing in the
  core reads it.
- The Community migrations image never contains the overlay set.

## The edition fence

`.github/scripts/check-edition-fence.sh` runs in CI (check **Edition fence**,
workflow `edition-fence.yml`) and in `.githooks/pre-commit`. It reads the git
index and fails when:

- a file under an overlay path is tracked (only `api/ee/README.md` may be), or
  `.gitignore` lacks an overlay line;
- a Go file imports the overlay (an `api/ee` package or a private module)
  without the `ee` build tag;
- the `ee` build tag appears outside `api/cmd/server/edition_ee.go`;
- web code imports the overlay directory directly (the default build reaches it
  only through the `@ee` alias), or names `src/ee` outside `web/next.config.*`;
- the commercial brand name appears in a tracked file or path (the word list
  lives in the script).

Run it by hand: `bash .github/scripts/check-edition-fence.sh`; its tests:
`bash .github/scripts/check-edition-fence.test.sh`.

## Paid-feature checklist

The pull request template carries the same list: key registered, gated through
the entitlement service, Community behaviour unchanged, docs badge.
