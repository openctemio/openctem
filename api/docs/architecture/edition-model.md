# Edition model, extension points and Community build guard rails

How OpenCTEM is split into a Community edition and a commercial edition, what Community must never
lose, where commercial code is allowed to live, and the checks that keep it out of this repository.

Status: **design, with the first guard rails planned**. Nothing in the extension-point or overlay
sections exists in code yet. The licence mechanism is designed in RFC-145 (enterprise licence
verification and entitlements); the limits that a hosted service applies are in
[limits and feature denies](limits.md).

## Editions

| Edition | What it is | Source |
|---|---|---|
| Community | The complete product for one team or many organizations on one installation | This repository, GPL-3.0 |
| Enterprise | The same core plus a small set of capabilities aimed at large organizations, compliance and partners | Core from this repository, plus a private overlay module built into a separate image set |
| Add-ons | Separately distributed components with their own runtime (for example a first-party collector, a first-party AI worker) and premium content bundles | Separate private components that speak the open protocols |
| Hosted service | The Enterprise images run by the vendor, with plan limits applied as entitlements | Same images as Enterprise |

There is one product codebase. This repository is the only place product code is written. The
Enterprise overlay is a small add-on to it, not a fork: it holds no copy of the core, and it is pinned
to a core commit. A core release tag builds the Community images (public) and, in a separate private
job, the same tree plus the overlay as the Enterprise images, both signed in the same run. An
Enterprise image without a licence behaves exactly like Community, so an installation can run it from
day one and add a licence later.

## What Community never loses

- **Released code stays open.** Every release already published, and every commit already pushed to this
  repository, remains GPL-3.0. A capability that later becomes commercial is fenced only in versions
  after the change; the earlier releases keep it.
- **The security baseline is never licensed**: sign-in, MFA, passkeys and step-up, single sign-on login
  and enforcement, signed jobs and sensor trust, tenant isolation, scope verification and approvals,
  audit log viewing, search, export and chain verification, support-access controls, data export and
  erasure, VEX and CSAF statements, and security fixes.
- **The practitioner core stays open**: asset and finding management, scans and sensors, EASM,
  remediation, retest, reporting on demand, pentest and bug bounty workflows, the published ingest and
  AI-worker protocols, commodity integrations, the MCP server, bring-your-own-key AI triage, and the
  operator tooling (backups, Helm, Ansible, the all-in-one image).
- **A licence only adds.** It grants entitlement keys; it never denies or caps a Community feature, and
  it never makes an instance read-only or removes access to data (see RFC-145).
- **Moves are announced a release ahead**, with a continuity licence for installations that were using
  the capability, and data and tables are kept (the tables stay in the core schema).

## Deciding which edition a capability belongs to

1. Anything in the security baseline above is Community. It never moves.
2. Practitioner workflows and commodity integrations are Community.
3. Enterprise is for new capabilities that a director, executive or compliance buyer pays for: work
   across many organizations, compliance-grade retention and evidence, governance of models and
   policies at scale, enterprise service-management integration, disaster-recovery standby, long-term
   support.
4. An add-on is a separately priced component with its own runtime or content.
5. Hosted-only capabilities exist because the vendor hosts the service (billing, regions, hosted AI
   credits, status page).
6. A shipped capability may move only after scoring it on buyer persona, revenue value, how common the
   capability is, the effect on adoption, fork risk, effort to move and entanglement with core code;
   anything touching the security baseline is vetoed.

## Where commercial code lives

| Kind | Where | Why |
|---|---|---|
| In-process Enterprise features | A private overlay module, mounted into the module tree at build time at `api/ee/` and the web `(ee)` folders, compiled with the `ee` build tag (API) or `EDITION=ee` (web) | They need core transactions, authorization, tenant scope, audit and the read engine. A separate service would duplicate the tenant-isolation surface |
| Components with their own runtime | Separate private components on open protocols (sdk-go, CTIS), verifying the licence themselves | No GPL question, no second authorization surface |
| Billing, sign-up, metering | Separate private services of the hosted service | Not part of the product a customer installs |
| Generic seams, the entitlement key registry and the licence verifier | This repository | Seams are plain, documented interfaces with a Community default |

The overlay has to compile **inside** the `github.com/openctemio/openctem/api` module, because Go's
`internal` rule stops any other module from importing the core's `internal` packages.

### Extension points (designed)

`api/internal/extension` holds a registry and the seam interfaces; the overlay registers into it from
`init()` and nothing in the Community build imports the overlay.

- A module implements `Key() string` and `Register(*Registry) error`.
- The registry accepts routes, controllers, permission ids, audit event types, settings keys, a
  migrations file system and tenant-data hooks. The core mounts every route under `/api/v1/...`
  **wrapped with tenant middleware, the module's permission and `RequireAddon(key)`**, and wraps
  controllers with the same entitlement and module guards, so an overlay route cannot be mounted
  without an entitlement key and a permission.
- Tenant-data hooks (organization deletion, personal-data export and erasure, retention) make the
  existing privacy duties cover overlay tables.
- Behaviour seams inside core flows (for example a retention guard or a report brand) default to no-op
  in Community. Each seam is generic, documented and has a test of the Community behaviour.
- Dependencies handed to a module are core interfaces only: a tenant-scoped transaction helper, the
  entitlement service, the audit recorder, authorization, the outbox and the `pkg/httpsec` client. No
  raw database pool and no global state.
- `internal/server/edition_ee.go` (build tag `ee`) is the only file that imports the overlay;
  `edition_ce.go` (tag `!ee`) sets the edition to `community`. The version endpoint reports it.
- Generated contracts (OpenAPI, route permissions) are produced per edition: Community artefacts never
  contain overlay routes.

### Web

`next.config.ts` aliases `@ee` to the overlay folder when `EDITION=ee` and to an empty stub
(`src/ee-stub`: empty `navItems`, `settingsEntries`, `widgets`, `consolePages`) otherwise. Overlay
pages live in an `(ee)` route group present only in Enterprise builds. Each overlay navigation,
settings or widget entry names its entitlement key and is hidden unless the entitlements endpoint
grants it. Community shows no plan wording or upsell. Overlay i18n catalogs (en and vi) merge at build
time, and overlay pages use the same shared components as the rest of the console.

### Database

The overlay has its own migration set, tracked in `ee_schema_migrations`, applied by the same
`openctem-migrate` after the core set. Overlay tables are prefixed `ee_`, carry `tenant_id` with
`ON DELETE CASCADE` and the same RLS policy pattern. Core migrations never reference `ee_` tables;
overlay migrations may reference core tables and are exercised against core `develop` nightly. Moving
back from Enterprise to Community leaves the `ee_` tables unused and breaks nothing. A capability that
moves keeps its existing tables in the core schema, so data returns when a licence is applied.

## Entitlements

Every paid capability is behind one entitlement key from the registry in `pkg/domain/limits`, checked
only through `entitlement.Service`. There is no `if hosted` branch in core code: a deployment's
capabilities and entitlements decide what appears, and plan limits of a hosted service are
entitlements, not code paths. `tests/unit/entitlement_keys_test.go` already fails on plan, tier or
edition checks outside the entitlement service and lists every key; it is extended to require that
every registry key is documented. The plan words that exist today without a user (a reserved preset
tier field) are removed. See [limits and feature denies](limits.md) and RFC-145.

## Guard rails for the Community build

These keep commercial code out of this repository. They are the first work item, before any seam.

1. `.gitignore` ignores `api/ee/*` (only `api/ee/README.md` is tracked), `web/src/ee/`,
   `web/src/app/(ee)/` and `web/console/src/app/(ee)/`.
2. A required CI check `edition-fence` fails when: a tracked file exists under those paths other than the
   README; `go list -deps ./...` without tags contains an `api/ee` package or any module of the
   private overlay; the `ee` build tag appears outside `internal/server/edition_ee.go` and the test fixture;
   a commercial brand string appears in the diff; or web code imports `@ee/` other than through the
   alias.
3. A pre-commit hook in `.githooks` runs the path and brand checks locally.
4. CODEOWNERS requires a maintainer for `api/internal/extension/`, `web/src/ee-stub/`,
   `api/pkg/domain/limits/`, `.gitignore` and `cmd/server/edition_*.go`, and the same paths are listed in
   `.github/security-paths.yml`, because seams wrap authorization.
5. The pull request template has a "paid capability?" checklist: the tier from the rules above; for a
   non-Community capability only a generic seam and a registry key land here; no plan words; no brand
   strings; security baseline untouched.
6. A small fixture overlay under `api/internal/extension/testdata` is mounted and built with the `ee`
   tag in CI, so a core change that breaks a seam fails in the open pull request without any commercial
   code being present.
7. Contributor and agent rule: commercial code is written only in the private overlay's repository and
   is never pushed here, not even on a branch. If it happens: delete the branch and treat the content
   as published.

## Day-to-day workflow

| Situation | What happens |
|---|---|
| Ordinary feature or fix (the vast majority) | One pull request here, as today |
| Enterprise feature that fits an existing seam | One pull request in the overlay |
| Enterprise feature that needs a new extension point | A small generic seam pull request here (with a Community default and a test), then an overlay pull request that bumps its pin and uses it |
| Core refactor that breaks a seam | The fixture overlay fails in the same pull request here; a break in the real overlay shows in its nightly build against `develop` |
| Release | One tag builds both image sets from the same core commit, signed in the same run |
| Security fix | Fixed once here; both image sets carry it |

The overlay's own CI builds the core at the pinned commit plus the overlay, runs core and overlay
tests, checks migration order for the two sets, scans Go and npm licenses (refusing copyleft outside
the core), produces an SBOM and signs the images.

## Licences of the repositories

The core and the sensor are GPL-3.0. The SDK and the protocol, feed and deployment repositories are
Apache-2.0, which lets separately distributed components link them. A contributor license agreement
lets the maintainer offer the project under other terms; commercial code is never contributed here.

## Shipped and planned

| Item | State |
|---|---|
| Deny-based entitlement service, operator limits and feature denies | Shipped |
| Entitlement key guard test | Shipped (extension to registry keys planned) |
| Licence verification, subscription page, grants (RFC-145) | Designed |
| `edition-fence`, ignore rules, hook, CODEOWNERS, template checklist | Planned, first |
| `internal/extension`, `edition_*.go`, web alias and stub, second migration set | Designed |
| Overlay build, signing and private image distribution | Designed (outside this repository) |
