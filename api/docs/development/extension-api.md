# Extension API: building your own edition

OpenCTEM Community is an extensible platform. Anyone can build their own
edition: a separate Go module that requires the core, adds one or more
extensions written against the public extension API, and calls the core's
server entry point. The Enterprise edition is one such custom build; it uses
exactly the API described here and nothing else.

| Part | Where |
|---|---|
| Back-end API | [`api/pkg/extension`](../../pkg/extension/doc.go) |
| Server entry point | [`api/pkg/server`](../../pkg/server/server.go): `Main(exts ...extension.Extension)` |
| Test helpers | [`api/pkg/extension/extensiontest`](../../pkg/extension/extensiontest/extensiontest.go) |
| Reference extension | [`api/pkg/extension/example`](../../pkg/extension/example/example.go) |
| Reference custom build | [`api/examples/custombuild`](../../examples/custombuild/main.go) |
| Web API | `web/src/lib/extension` (navigation, settings, slots, override allowlist, message catalogs) |
| Where paid code goes, the fence | [editions](editions.md) |

## Build your own

```
go mod init example.com/myedition
go get github.com/openctemio/openctem/api@<version or commit>
```

```go
// cmd/openctem-server/main.go
package main

import (
	"example.com/myedition/myext"
	"github.com/openctemio/openctem/api/pkg/server"
)

func main() { server.Main(myext.Extension()) }
```

```go
// myext/myext.go
package myext

import "github.com/openctemio/openctem/api/pkg/extension"

func Extension() extension.Extension {
	return extension.Extension{
		APIVersion: 1,             // the API version written for, as a literal
		Name:       "myext",       // unique in the build, reported by /api/v1/version
		Version:    "v0.1.0",
		Schema:     "myext",       // its own Postgres schema
		Migrations: migrations,    // fs.FS of VERSION_name.up.sql / .down.sql
		ConfigKeys: []string{"MYEXT_ENDPOINT"},
		Routes:     routes,
	}
}
```

`go build ./cmd/openctem-server` gives one binary that is the whole server: the
core, its bundled operator commands (picked by the name it runs under) and
every extension passed to `Main`. A build may pass several extensions; their
names, schemas and config keys must be unique, and at most one may provide
grants. The server checks the whole build before anything starts and refuses
to start on a mistake.

## Dependency rule

- An extension imports `api/pkg/extension`, the other public `api/pkg/...`
  packages (best effort, not versioned before 1.0), its own packages and its
  own dependencies. Go refuses `api/internal/...` from another module, so
  this rule is enforced by the compiler.
- The core imports nothing of any extension and never names a grant key, a
  plan, a tier, an edition or a brand.
- The web build reaches extension code only through the `@extension/*` alias
  (see [Web](#web)).

## Extension points

Each point is named by function, has a Community default that keeps today's
behaviour, and is covered by the example extension and a contract test.

| Point | Shape | Notes |
|---|---|---|
| Grants | `Grants func(ctx, Deps) (GrantProvider, error)` | things that are off unless granted; at most one provider per build; a failing provider leaves every grant off ([RFC-145](../rfcs/RFC-145-enterprise-licence-and-entitlements.md) lists the guarantees every provider keeps) |
| Controllers | `Controllers func(ctx, Deps) ([]Controller, error)` | run by the core controller manager; `Exclusive` ones on one replica; an error stops the start |
| Routes | `Routes func(ctx, Router, Deps) error`, `Route{Method, Path, Permission, Grant, Handler}` | mounted at `/api/v1<Path>` behind authentication, the organization from the credential, membership, CSRF, the core permission and the grant; core routes and planes (`/admin`, `/auth`, `/internal`, `/sensor`, `/scim`, `/tenants`, `/ci`, `/mcp`, `/oauth`, `/platform`, the credential roots, ...) cannot be used; the caller is in `CallerFrom(ctx)` |
| Migrations | `Schema` + `Migrations fs.FS` | in the extension's own schema; reference core tables only by primary key and `tenant_id` (`ON DELETE CASCADE`) |
| Config keys | `ConfigKeys []string` | read through `Deps.Settings`; core keys refused; any other key reads as empty |

What the core hands over (`Deps`) is interfaces only: `Store` (one transaction
per call; `TenantTx` marks the organization, and every query still filters by
`tenant_id`), `Settings`, `Entitlements`, `AdminAudit` (read access to the
administrators' audit chain and a forward cursor), `Log` and `Env`.

Points planned with their first users (each lands with that user, never
ahead): route surfaces beyond tenant routes (platform console, SCIM, internal
API), extension permissions, an audit recorder, a secret store, tenant-data
export and erasure hooks, event subscribers, notification channels,
connectors, dashboard metrics, report sections, and behaviour seams in core
flows (brand, retention, member lifecycle, sensor admission).

## Web

- `EXTENSIONS=on` builds the web app with the extension's web code copied to
  `web/src/extensions/` and its pages to `(extensions)` route groups (all
  git-ignored here); unset, the `@extension/*` alias resolves to the empty
  modules in `web/src/extension-default/`. A production build without the
  switch refuses to run while a mount directory exists.
- Navigation and settings rows carry `module`, `permission` and `grant`. A row
  whose grant is off is not rendered, so a build without a grant shows exactly
  the Community UI: no locked items, no upsell. The API gate is the security
  boundary; the web only hides.
- Strings go through the message catalogs (en and vi); an extension adds keys
  and never replaces core ones.

## Security model

A compiled-in extension is fully trusted: it runs in the server's process
with its memory and database credentials. The API's guarantees are guard
rails and correct defaults, not a sandbox. Untrusted third-party code never
runs in-process; it uses the public network surfaces instead (REST API with
scoped API keys, CTIS ingest, the sensor protocol, notification webhooks,
MCP). `/api/v1/version` lists the extensions a build contains, so an operator
and support can tell a stock build from a custom one.

## Testing

- `extensiontest.Deps(db, e, opts)` returns the `Deps` the core would hand
  `e`, built by the core's own implementations; `extensiontest.DB(t, e)` is a
  private test database with the core migrations and `e`'s migrations
  applied (it needs `DATABASE_URL` to name a database ending in `_test`).
- Every extension's tests include: a route without the grant answers 403
  `ADDON_NOT_LICENSED`; another organization's data is never visible (by id
  and by filter); migrations up, down, up.
- Core CI compiles and tests the example extension and the custom build on
  every pull request; `pkg/extension/testdata/api.golden` records the exported
  surface and changes to it get maintainer review.

## Versions

- `extension.APIVersion` is 1 until the core's 1.0 release. An extension
  states the version it was written for as a literal, and the server refuses
  to start on a mismatch.
- Before 1.0 a breaking change goes expand (new form added, old kept), migrate
  the extensions, contract (old form removed) within one release train, and
  is listed under "Extension API" in the release notes. After 1.0 the `api`
  module follows semantic versioning.
- A custom build pins the core in its `go.mod` (a release tag or a commit).
  Build and test it against the core's development branch regularly to catch
  breaks early.

## Moving an installation between editions

| From | To | How |
|---|---|---|
| Community vX | a custom build on core vX | swap the images; migrations apply the core set, then each extension's set in its schema |
| a custom build | Community, same core version | swap back; the extension schemas stay and are ignored; its permission ids in stored roles are ignored |
| a custom build on vY | Community vX, X < Y | not supported: restore the backup taken before the upgrade |

Nothing else changes on a swap: database, users, sessions and signing keys,
sensors (no re-pairing), the encryption keys, SSO settings, API keys.

## Licence

The core is GPL-3.0. A custom build that compiles an extension into the core
and is distributed is a work based on the core and is distributed under the
GPL. Closed third-party code uses the out-of-process surfaces listed under
[Security model](#security-model).
