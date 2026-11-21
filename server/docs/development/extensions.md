# Extensions: where extension code goes

OpenCTEM can be built with extensions: code written against the public
extension API and compiled into a build. A build with extensions is its own Go
module that imports this core's public packages and its extensions, and calls
`server.Main()` ([extension API](extension-api.md)). The default build, the
images built from this repository, contains no extension.

**Rule: an extension's code is written in the extension's own repository. This
repository gets generic extension points and the grant seam only.** Never push
extension code here, not even to a branch.

## Extension points and grants

An extension point is a named, documented seam in the core with a default that
does nothing. A grant is something that is off unless a build's grant provider
grants it; the default build has no provider, so nothing is granted and nothing
depends on a grant. Anyone can use both to add an optional module to their own
build.

What lands here when an optional module needs something from the core:

1. A key, registered in [`pkg/domain/limits`](../../pkg/domain/limits/registry.go)
   with a description. `tests/unit/entitlement_keys_test.go` fails on a key
   without one, on a key built from a string literal, and on an unknown key.
2. A generic extension point (an interface whose default does nothing),
   consulted through the entitlement service
   ([limits and feature denies](../architecture/limits.md)). The core asks
   only that service; the same test file refuses a check of anything else by
   name.
3. Tests that the default build's behaviour is unchanged.

Guard rails that hold for every extension point and every grant:

- a grant only adds: it never yields a limit or a deny, and a failing provider
  leaves grants off without changing anything else;
- sign-in, SSO, MFA, audit and security controls are never behind a grant;
- the default build renders nothing for an absent module: no locked items and
  no placeholders.

## Extension-point locations (maintainer review via CODEOWNERS)

| Path | Role |
|---|---|
| `server/pkg/extension/` | the public back-end extension API |
| `server/pkg/server/` | `Main()`, the entry point a custom build calls from its own Go module |
| `server/pkg/domain/limits/` | limit keys and their descriptions, and the grant seam |
| `web/src/lib/extension/`, `web/src/extension-default/` | the public web extension API and the empty modules the `@extension/*` alias resolves to in the default build |
| `web/src/extensions/`, `web/src/app/**/(extensions)/`, `web/console/src/app/**/(extensions)/` | web mount points: git-ignored, empty in this repository; an extension's build copies its web code there |

A build with extensions is its own Go module: it requires
`github.com/openctemio/openctem/server`, imports its extensions and calls
`server.Main()`. Go then lets it use only the public `server/pkg/...` packages,
and its dependencies stay in its own `go.mod`. Nothing of an extension's Go
code is ever placed in a checkout of this repository.

## The core boundary check

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

An extension keeps its tables in its own schema. The core is written so that
the default build runs unchanged on a database that also holds such a schema (a
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

The pull request template carries the list: named by function with a default
that keeps today's behaviour and a first user, covered by the example
extension and a contract test, gated only through a grant.
