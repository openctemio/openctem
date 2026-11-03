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
| `api/internal/extension/` | registry the overlay registers routes, controllers, permissions and settings into |
| `api/cmd/server/edition_*.go` | the build switch: `edition_ee.go` carries the `ee` build tag and is the only file that may |
| `api/pkg/domain/limits/` | entitlement keys and their descriptions |
| `api/ee/`, `web/src/ee/`, `web/src/app/(ee)/`, `web/console/src/ee/`, `web/console/src/app/(ee)/` | overlay mount points: git-ignored, empty in this repository |
| `web/src/ee-stub/` | what the `@ee` alias resolves to in the default build |

The `extension` registry and `ee-stub` directories are created with the first
extension-point change; the CODEOWNERS entries exist already.

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

## Extension data in the database

An extension keeps its tables in its own schema. The core is written so that a
Community build runs unchanged on a database that also holds such a schema (a
rollback, or a restored backup): every core probe of the catalog is limited to
the core schema, and nothing in the core reads another schema
(`internal/migrate/extension_schema_db_test.go` proves migrate up and down, the
start-up schema check and the administrator bootstrap with clashing table
names).

Key rotation (`cmd/rekey`) re-encrypts only the locations it lists, all in
the core schema. Until a rekey seam lets an extension list its own encrypted
columns, **an extension stores no value encrypted with `APP_ENCRYPTION_KEY`**.
The rotation's sweep covers every schema, so a value that breaks this rule
stops the rotation (named, nothing committed) instead of being left unreadable
under the new key (`TestRekey_SweepCoversExtensionSchemas`).

## Paid-feature checklist

The pull request template carries the same list: key registered, gated through
the entitlement service, Community behaviour unchanged, docs badge.
