# Asset coverage

Design: [RFC-093](../rfcs/RFC-093-asset-coverage.md).

Every asset gets every capability its type needs, and a pair that goes
uncovered is visible. Three parts:

| Part | Where |
|---|---|
| **Policy**: per type, the capabilities it needs, how often, the facts that must hold (`resolves`, `web_port`, `scope_entry`) and the type a run must produce | `configs/asset-types.yaml` (`coverage:`), read with `coverage.Rules()` / `coverage.RulesFor()` |
| **Ledger**: one row per asset, capability and vantage: state, reason, last attempt and success, outcome, next due | table `asset_coverage`, `internal/infra/postgres/asset_coverage_repository.go` |
| **Loop**: the `asset-coverage` controller (one replica, every `ASSET_COVERAGE_INTERVAL`) | `internal/app/coverage` |

## States

`due` → `queued` → `covered` | `failed`; `blocked` (scope gate, guardrail,
placement or budget; the reason names which; never a gap), `paused` (window,
hold, switch), `not_applicable` (a precondition does not hold; the reason
names it). A pair is a **gap** when it applies and has gone without a success
for more than twice its cadence.

## Reconcile

For each tenant with active assets and each rule, one statement adds the
missing rows (due now, or not applicable with the failing predicate) and
flips rows whose precondition changed. A core type's rule does not apply to
its alias sub-types (an `open_port` follows its own rules, not `service`'s).
Idempotent; bound to the tenant.

## Explanation

`GET /api/v1/assets/{id}/coverage` (`assets:read`, data scope by id: out of
scope is 404): one entry per rule of the asset's type (a rule with no row is
`due` / `not_planned`), then any other ledger row of the asset (platform
checks such as `dns.dangling`, connectors).

## Planning and settlement

Each pass, per tenant, after reconciling:

1. **Settle** every run that holds `queued` pairs: `completed`/`partial` →
   `covered` (outcome `ok`, or `no_output` when the rule expects a web origin
   and none of the asset was observed since it was queued); targets the run
   did not finish, and runs that `failed`, were `canceled`, `timeout` or
   `blocked` → `failed` with the run's error, failure streak + 1, due again
   after 1 h doubled per failure (at most the cadence, at most a day). A run
   not finished after a day fails its pairs as stalled.
2. **Plan**, unless the tenant's scan approval mode in force is Strict: for
   each stage capability of the policy (never an intrusive one; platform
   checks run on their own schedule), take up to 200 due pairs (priority,
   then oldest), within the tenant's daily budget
   (`ASSET_COVERAGE_DAILY_BUDGET`, default 5000 attempts per 24 h), and call
   `scan.Service.StartCoverage`: the targets pass the one dispatch gate as
   the system (scope entries only) at the capability's tier; refused targets
   become `blocked` with the gate's code (rechecked after 6 h); the rest run
   on the tenant's reused ad-hoc scan "Continuous coverage: <capability>"
   (tag `auto-coverage`) with the stage's default tool, and become `queued`.
   While that scan still has an active run the batch waits (one run per
   capability and tenant at a time: back-pressure).

An open port is addressed as `host:port`; names and origins by name.
With the loop on, automatic enrichment of new assets is off: the loop
resolves and looks up every asset its policy names.

## Other writers

- DNS checks (`internal/app/easmdns`): rows `dns.dangling` and `dns.email`.
- Connector rotation (`internal/app/scancoverage`): rows `network_va.connector`.
