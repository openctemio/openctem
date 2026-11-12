# Editions: where paid-feature code goes

This repository is the open core and the only place product code is written.
Paid features live in a separate extension repository; the Enterprise build
is one custom build of OpenCTEM: its own Go module that imports this core's
public packages and its extension, and calls `server.Main()`. The Community
build never contains extension code.

**Rule: paid-feature code is written only in its extension repository. The
core gets generic extension points and the grant seam only.** Never push
extension code here, not even to a branch.

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
| `server/pkg/extension/` | the public back-end extension API (created with its first point) |
| `server/pkg/server/` | `Main()`, the entry point a custom build calls from its own Go module |
| `server/pkg/domain/limits/` | limit keys and their descriptions, and the grant seam |
| `web/src/lib/extension/`, `web/src/extension-default/` | the public web extension API and the empty modules the `@extension/*` alias resolves to in the default build |
| `web/src/extensions/`, `web/src/app/**/(extensions)/`, `web/console/src/app/**/(extensions)/` | web mount points: git-ignored, empty in this repository; an extension's build copies its web code there |

A build with extensions is its own Go module: it requires
`github.com/openctemio/openctem/server`, imports its extensions and calls
`server.Main()`. Go then lets it use only the public `server/pkg/...` packages,
and its dependencies stay in its own `go.mod`. Nothing of an extension's Go
code is ever placed in a checkout of this repository.

## The edition fence

`.github/scripts/check-edition-fence.sh` runs in CI (check **Edition fence**,
workflow `edition-fence.yml`) and in `.githooks/pre-commit`. It reads the git
index and fails when:

- a file under a web mount point is tracked, or `.gitignore` lacks a mount
  line;
- `server/go.mod` has a `replace` directive (the core builds from public sources
  and works as a dependency of a custom build);
- web code imports a mount point directly (the default build reaches it only
  through the `@extension/*` alias), or names `src/extensions` outside the web
  build configs (`web/next.config.*`, `web/console/next.config.*`);
- a restricted word appears in a tracked file or path. The list is not in this
  repository: CI reads it from the `FENCE_RESTRICTED_WORDS` secret, and a
  local clone may keep it in `.git/info/restricted-words` (one word per line).
  Without a list this rule is skipped and the script says so; pull requests
  from forks have no secrets, and the merge-queue run applies the rule.

The script prints the file and line of a hit, never the matched word. Run it by
hand: `bash .github/scripts/check-edition-fence.sh`; its tests:
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

## Extension-point checklist

The pull request template carries the list: named by function with a
Community default and a first user, covered by the example extension and a
contract test, never gated by plan, tier, edition or brand name.
