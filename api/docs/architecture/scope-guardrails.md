# Scope guardrails

The platform's own limits on what an organization may put in scope and what
a sensor may probe. They protect third parties from a careless or malicious
organization, so no tenant setting turns them off. Design: RFC-054 §8 and
[RFC-154](../rfcs/RFC-154-blocked-target-names.md).

## The rules

| Rule | Refusal | Who can change it |
|---|---|---|
| Public suffixes, as an entry or a wildcard root (embedded Public Suffix List) | `PUBLIC_SUFFIX` | nobody (code) |
| Shared provider apexes as wildcard roots (`*.amazonaws.com`, ...) | `PUBLIC_SUFFIX` | nobody (code) |
| Loopback, link-local and cloud metadata addresses, "this network", the whole address space | `DENY_LIST` | nobody (code) |
| Public ranges wider than the caps | `CIDR_TOO_LARGE` | operator, environment (`SCOPE_MAX_PUBLIC_CIDR_V4/V6`) |
| The operator's names and ranges | `DENY_LIST` | operator: `SCOPE_DENY_EXTRA` (always on), plus names a platform owner adds in the console |
| Government and military names (`*.gov`, `*.mil`, `gov.<cc>`, `mil.<cc>`, `gouv`, `gob`, `go`, `govt` under a country code, `gc.ca`, ...) | `GOVERNMENT_NAME` | platform owner, console: on by default; per-organization exceptions |

Where they run:

- **Adding scope**: `scope.Service` (single add, bulk add, preview,
  replacement, re-activation, CI trusts), the bounty program import preview,
  EASM rule suggestions and confirm-scope (through `scope.Service`), New scan
  wildcard targets (`scan.validateSelectorTargets`), network seeds (ranges only).
- **Dispatch**: `Guardrails.Denies` in the ownership gate
  (`easm.ActiveGate`, state `platform_denied`), the scope authority
  (`scopeauth.Load` drops refused entries), the MCP scope check, and the
  signer ledger snapshot (refused entries are left out).

Every check that knows the organization calls `Guardrails.For(tenantID)`, so
that organization's exceptions apply. A check without an organization applies
none (fail closed).

## Blocked target names policy

`pkg/domain/scope/blocked_names.go` holds `NamePolicy`, one shared,
concurrency-safe snapshot: the government rule switch, the console names and
the live exceptions. The server sets it as the platform's policy
(`SetPlatformNamePolicy`) before it builds any guardrails, so every copy of
`Guardrails` (they are passed by value) reads the same policy.

`internal/app/scopenames` stores and changes it:

- the switch, the console names and the longest exception live in
  `platform_settings` key `scope_blocked_names` (RFC-079 store, compare and
  swap on `version`);
- exceptions live in `scope_name_exceptions` (organization, name,
  `include_subdomains`, reason, authorisation reference, granted by, granted
  at, expiry, revocation). One live exception per organization and name;
  organization deletion removes them (foreign key);
- after every change the replica reloads the snapshot at once; other replicas
  reload a snapshot older than 15 seconds on their next check. A failed reload
  keeps the last snapshot; at start-up the snapshot is the rule on with no
  exceptions.

Exception semantics:

- it lifts the government and military rule only: never the operator's names,
  public suffixes, address rules or caps;
- exact name by default; with `include_subdomains`, the name and every name
  under it (a wildcard entry `*.name` needs `include_subdomains`);
- the name must sit under a government suffix and must not be the suffix
  (`gov.xx`) or a public suffix;
- the expiry is required, at most `max_exception_days` (default 365) from the
  day it is granted or extended, and is compared with the clock at every
  check, so an expired exception refuses at add and at dispatch without a job;
- it widens nothing else: the organization still adds a scope entry through
  every rule (domain proof when the platform requires it, approvals, step-up,
  scan governance, exclusions, the signer ledger).

## Console

Scanning > Platform scanning > Blocked names. Any console reader sees the
policy and the exceptions. Changes need `platform.settings.scope_guardrails`
(platform owner only), a fresh authenticator code (route step-up) and a
reason:

| Route | What |
|---|---|
| `GET /api/v1/admin/settings/scope-blocked-names/` | policy (`government_rule`, `names`, `env_names`, `max_exception_days`, `second_approval`) |
| `PUT /api/v1/admin/settings/scope-blocked-names/` | change the policy |
| `GET /api/v1/admin/settings/scope-blocked-names/exceptions` | every exception with its state |
| `POST /api/v1/admin/settings/scope-blocked-names/exceptions` | grant |
| `POST .../exceptions/{id}/extend` | new expiry (an expired exception comes back) |
| `POST .../exceptions/{id}/revoke` | end it at once |

With `MANAGED_SERVICE` set, a grant, an extension and turning the rule off
need a second owner through the console's four-eyes approvals (actions
`scope_names.exception`, target = organization, name, subdomains and expiry
day; `scope_names.government_rule_off`, target `off`). Every change writes a
critical admin audit row (organization, name, reason, authorisation reference,
expiry, values before and after) and e-mails every administrator.

## Tenant view

A refused entry answers `400 GOVERNMENT_NAME`: "government and military
domains are blocked on this installation; your platform administrator can
grant an exception". Tenants never see the exceptions list, other
organizations' exceptions or the console setting.
