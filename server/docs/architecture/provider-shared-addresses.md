# Scope entries on provider shared addresses

**Status: SHIPPED** (the Scope page card, the hold setting, the review rule
guard, the classifier dataset checks). Scope model:
[RFC-054](../rfcs/RFC-054-scope-model.md); address classifier:
`pkg/domain/edgeaddr`.

A company name (a mail domain, a site behind a content delivery network)
often resolves to addresses a provider publishes for infrastructure many
organizations share: mail front ends, edge networks, managed front doors.
Those addresses are the provider's. They serve the provider's other
customers too, rotate often, and testing them follows the provider's rules.
A scope entry that names one (added by hand, from an import, or by a review
rule) authorizes active checks of someone else's infrastructure.

The Scope page shows such entries once, per provider, and asks one question.

## Which entries are listed

`scope.SharedProviderEntry` (`pkg/domain/scope/provider.go`) reads an
`ip_address`, `cidr` or `ip_range` entry and answers its provider when:

- the address lies inside a published shared front-end range
  (`edgeaddr.SharedFrontEnd`: classes edge, saas_hosting and cloud_shared,
  published-range basis only); or
- both ends of the CIDR or range do, and one published range holds the whole
  of it.

A range that only partly overlaps a shared range, an address a dedicated
published range holds (a dedicated prefix always wins), an address known only
from its network holder or a CDN header, and every name entry are not listed:
classification fails closed to "may be the organization's".

Only in-effect entries are listed; program entries (another organization's
scope) never are. Entries a person chose to keep scanning are not listed
again (`scope_provider_keeps`).

Under each provider the card also lists the addresses a person confirmed as
the organization's (an `ip_address` asset with a person-decided `confirmed`
attribution inside that provider's shared range), read within the caller's
data scope: each one is opened to keep or change that decision.

## The two answers

| Answer | API | Gate | What changes |
|---|---|---|---|
| Move to out of scope (recommended, the main action) | `POST /api/v1/scope/provider-addresses/move` `{"provider": "...", "preview": true}` first, then without `preview` | `attack_surface:scope:write`, no step-up (it only narrows) | Each listed entry becomes a `do_not_scan` exclusion of the same type and pattern, with the entry's origin and the reason "Shared <provider> address", and the entry is deactivated. All of it is saved in one transaction (`ScopeProviderRepository.SaveMove`) and sent to the job signer as one narrowing ledger change. An exclusion that already exists is kept and only the entry is deactivated. |
| Keep scanning | `POST /api/v1/scope/provider-addresses/keep` `{"provider": "..."}` | `attack_surface:scope:write` and a recent re-authentication (route and service) | One `scope_provider_keeps` row per listed entry (provider, dataset version, who, when). The entries stay in scope, leave the card, and are never held. |

`GET /api/v1/scope/provider-addresses` (`attack_surface:scope:read`) is the
card: per provider the entries (id, type, pattern, origin, status, created
at), their count, and the person-confirmed addresses, plus the classifier's
dataset version and whether the organization holds unanswered entries. An
unknown provider, or one with nothing left to answer, is 404 for both
actions.

The exclusion stays on the address. Names that resolve to it are not
excluded with it: a shared front end never propagates an exclusion to the
names behind it (`scope.PropagatingAddresses`, owner decision 2026-10-30).
Those names stay in scope and keep their web checks by name.

Nothing is deleted: the entries remain, deactivated, in scope history, and
the exclusions are new rows. Undo is the ordinary exclusion delete and entry
activation (both ask for a re-authentication because they widen).

### Audit

- Move: `scope_exclusion.created` for each new exclusion,
  `scope_target.deactivated` for each entry (before and after), and one
  `scope_target.provider_moved` summary with the provider, the counts and
  every entry and exclusion id.
- Keep: one `scope_target.provider_kept` event, high severity, with the
  provider and the entry ids.

## Holding unanswered entries (`hold_provider_entries`)

Until someone answers them, unanswered entries on a provider's shared
addresses are paused (owner decision 2026-11-19). The organization's scope
setting `hold_provider_entries` (Settings > Scope, "Hold shared provider
addresses until answered"; `PUT /api/v1/scope/settings`, scope approvers
with step-up) controls it:

- **On (default, also when never set)**: an unanswered entry authorizes
  nothing. `scopeauth.Load` asks the scope service (`HeldProviderEntries`,
  the `scopeauth.ProviderHolds` interface) and drops held entries from the
  authority. An address only a held entry covers is refused by the
  active-probe gate with the state `provider_held` (refusal code
  `provider_address`) instead of being probed or getting the low-impact
  checks of an unclassified asset; typed targets are refused by the
  act-scope check with the same code. A scan run lists them as skipped with
  the reason `provider_address`; no job targeting them is built, signed or
  sent. Names resolving to the address are not affected. The card shows a
  banner saying scanning of these addresses is paused and why.
- **Off**: such entries authorize active checks like any other entry.
  Turning it from on to off lifts every hold of the organization at once, so
  it needs the critical re-authentication (the same as **Keep scanning**,
  whatever the organization's sensitive tier says): a stale session gets
  `403 STEP_UP_REQUIRED` and nothing changes. The change is audited at high
  severity (`provider_hold_lifted`) and every administrator gets the notice
  "Hold on shared provider addresses turned off".

Undo is one step per provider: **Keep scanning** (step-up, audited) resumes
active scanning of those entries at once; **Move to out of scope** keeps the
entries (deactivated) and their history and never excludes the names. A
settings read that fails refuses (the gate dispatches nothing), as every
other authority lookup does.

## Review rules never add one

Accepting a review rule whose pattern is a shared provider address or a
range wholly inside one is refused with `PROVIDER_SHARED_RANGE`
(`internal/app/easm/review_rules.go`): a person adds such an entry, after the
warning, on the Scope page.

## The provider range list

`pkg/domain/edgeaddr/dataset.json` is built by
`server/scripts/edgeaddr-dataset.py` from the providers' own published lists
(a maintainer runs `fetch` and `build`, reviews the diff and commits it; the
platform itself never downloads them). Its tests pin:

- no dedicated prefix overlaps a shared one, and `Address`, `Range` and
  `Name` agree with `SharedFrontEnd` for every prefix;
- an address in a provider's network outside the published service lists
  (a cloud instance, a static or customer-owned address) is never shared;
- IPv6 forms (upper case, uncompressed, IPv4-mapped) classify by value, and
  an address with a zone is never shared; a NAT64 form is not read as its
  embedded address yet;
- `TestEdgeaddr_DatasetAge` fails once the dataset's `version` date is more
  than 30 days old, so CI asks for a refresh at least monthly.

## Tenant isolation

The tenant comes from the authenticated context. Every statement carries it:
the entries come from the tenant's own list, the keep rows are inserted only
for the tenant's own entries (`JOIN scope_targets ... AND t.tenant_id = $1`),
the move refuses an entry or exclusion of another tenant, and the
person-confirmed addresses are read with the tenant and the caller's data
scope. One organization's answer never changes another's entries, and the
card never says whether another organization lists the same address.

## Key files

- `pkg/domain/scope/provider.go`: which entries name a provider's shared
  addresses.
- `internal/app/scope/provider_addresses.go`: the card, the move, the keep,
  the hold.
- `internal/app/scopeauth/authority.go`: held entries cover nothing.
- `internal/app/easm/active_gate.go`, `internal/app/actscope/checker.go`:
  the `provider_held` / `provider_address` refusal.
- `internal/infra/postgres/scope_provider_repository.go`, migration
  `20261119023815_scope_provider_keeps`.
- `internal/infra/http/handler/scope_provider_handler.go`.
- `web/src/features/scope/components/scope-provider-addresses-card.tsx`.
