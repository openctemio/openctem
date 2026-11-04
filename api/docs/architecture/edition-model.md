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
| In-process paid features | An extension in its own repository; the paid build is its own Go module that requires `github.com/openctemio/openctem/api`, imports the extension and calls `api/pkg/server.Main()` | They need core transactions, authorization, tenant scope, audit and the read engine. A separate service would duplicate the tenant-isolation surface |
| Components with their own runtime | Separate components on open protocols (sdk-go, CTIS), verifying their licence themselves | No second authorization surface |
| Billing, sign-up, metering | Separate services of the hosted service | Not part of the product a customer installs |
| The public extension API, the grant seam and the guarantees of any grant provider | This repository | Plain, documented, versioned interfaces with a Community default |

A paid build is one custom build of OpenCTEM, made the way anyone can make one. Because it is a
separate Go module, Go's `internal` rule lets it import only the public `api/pkg/...` packages: the
compiler enforces "public API only", and the extension's dependencies stay in its own `go.mod`.

### Extension points

`api/pkg/extension` is the public back-end API: one `Extension` value per extension, several per
build, each field optional with a tested Community default. Routes are mounted only behind
authentication, the organization from the credential, membership, CSRF, the declared permission and
grant; dependencies handed to an extension are interfaces (a tenant-scoped store, declared settings,
grants, the audit recorder, the logger), never a raw pool. Each point lands with its first user.
`/version` lists the extensions a build contains. The guide is
[editions](../development/editions.md).

### Web

The web app reaches extension code only through the `@extension/*` alias: the empty modules in
`src/extension-default` by default, or an extension's code copied to `src/extensions` and its pages to
`(extensions)` route groups when built with `EXTENSIONS=on`. Each navigation or settings row names
its module, permission and grant, so a build without a grant renders exactly the Community UI: no plan
wording, no locked items, no upsell.

### Database

Each extension owns one Postgres schema with its own migration tracker, applied by the core migration
runner after the core set. Extension tables reference only core primary keys and `tenant_id` with
`ON DELETE CASCADE`; core migrations never reference an extension schema. Moving back to Community
leaves the extension schema unused and breaks nothing.

## Entitlements

Every paid capability is behind one entitlement key from the registry in `pkg/domain/limits`, checked
only through `entitlement.Service`. There is no `if hosted` branch in core code: a deployment's
capabilities and entitlements decide what appears, and plan limits of a hosted service are
entitlements, not code paths. `tests/unit/entitlement_keys_test.go` already fails on plan, tier or
edition checks outside the entitlement service and lists every key; it is extended to require that
every registry key is documented. The plan words that exist today without a user (a reserved preset
tier field) are removed. See [limits and feature denies](limits.md) and RFC-145.

## Guard rails for the Community build

1. The web mount points (`web/src/extensions/`, `(extensions)` route groups) are git-ignored and
   empty here; no extension Go code is ever placed in a checkout of this repository.
2. The required check **Edition fence** fails on a tracked mount-point file, a direct import of a mount
   point, a `replace` directive in `api/go.mod`, or a restricted word (the list is kept out of this
   repository). The pre-commit hook runs the same script.
3. CODEOWNERS requires a maintainer for `api/pkg/extension/`, `api/pkg/server/`,
   `api/pkg/domain/limits/`, `web/src/lib/extension/` and the fence.
4. The pull request template has an "Extension point?" checklist.

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
