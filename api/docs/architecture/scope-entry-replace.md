# Replacing a scope entry's pattern

**Status: SHIPPED.** Scope model: [RFC-054](../rfcs/RFC-054-scope-model.md).

A scope entry's type and pattern are never edited in place: the entry's
approvals, its audit history and the scans that name it are bound to the
pattern. Correcting a mistyped pattern (a wrong address range, a misspelt name)
used to take a removal and an add, which could briefly leave real targets out
of scope. **Replace pattern** does it as one change: a new entry of the same
type with the new pattern takes the old entry's place.

## Behaviour

`POST /api/v1/scope/targets/{id}/replace` with `{"pattern", "reason"}`
(`attack_surface:scope:write`, the permission that edits scope):

1. The old entry must be the caller tenant's (another tenant's id answers 404)
   and in effect (`409 ENTRY_NOT_REPLACEABLE` for a pending, inactive, expired
   or rejected entry; `409 ENTRY_SUPERSEDED` for one already replaced). Program
   entries (`PROGRAM_MANAGED`) and entries a CI trust manages
   (`CI_TRUST_MANAGED`) change through their owner. A reason is required
   (`REPLACE_REASON_REQUIRED`); the same pattern is refused
   (`REPLACE_SAME_PATTERN`). At most one replacement waits for approval at a
   time (`409 REPLACEMENT_PENDING`, also enforced by a partial unique index).
2. The new pattern runs every check a new entry runs: pattern validation, the
   platform guardrails (public suffixes, the deny list, CIDR caps), the
   duplicate check, then the one-off, request, tier and approval rules of the
   organization's scan approval mode, with step-up for the caller. A widening,
   a narrowing and an equal-size correction all follow the rule of adding an
   entry: never a weaker one. A member without the approve permission in
   Strict can only request a one-off entry for one name or address, exactly
   as when adding.
3. The new entry keeps the old entry's description, priority, tags, discovery
   setting, port and protocol limit, authorization source, tier and expiry,
   and records `supersedes_id`.
4. **In effect at once** (no approval needed): in one database transaction
   the new entry is created and the old one becomes `superseded` with
   `superseded_by_id`. The job signer's ledger accepts the new entry before
   anything is saved, and the old entry's removal is sent after (the usual
   widening-first, narrowing-after order of the ledger hook).
5. **Waiting for approval**: only the new entry is saved; the old entry stays
   in effect. When the replacement is approved (approve, self-approve, the
   activation of a leftover pending entry, or the settle job after the
   organization leaves Strict), the same transaction that puts it into effect
   retires the old entry. A rejected, expired or deleted replacement leaves
   the old entry as it was.

`POST /api/v1/scope/targets/{id}/replace/preview` takes the same body, runs
the same checks without step-up and saves nothing. Both answer
`ScopeReplaceResponse`: the old and new entries, `old_retired`,
`step_up_required`, the coverage `change` (`widens`, `narrows`, `added`,
`removed`, and address counts for address types), and the scan zones that
name the old range.

A superseded entry authorizes nothing and keeps its history. It cannot be
replaced, activated, deactivated or have its entry fields changed; it can be
deleted. The list shows it with the status filter "Replaced".

## Scan zones

For address entries, the response lists every scan zone with a range inside
the old pattern, with `suggested` ranges (the zone's ranges with those swapped
for the new pattern's addresses). A zone whose wider range merely contains the
old pattern is not listed. The replacement never changes a zone: the web
console offers a checkbox per zone, shown only to a caller with
`sensors:zones:write` and only when the replacement took effect, and then
calls `PATCH /api/v1/scan-zones/{id}`, which checks that permission and the
zone's own validation again. A caller without `sensors:zones:read` gets only
`zones_hidden`, the number of such zones.

## Audit

One event `scope_target.replaced` (high severity) on the old entry, with
`old_pattern`, `new_pattern`, `old_id`, `new_id`, `reason`, `new_status`,
`old_retired` and `widens` in its metadata and both entries as before and
after. The later approval is audited as any approval.

## Threat model

| Threat | Control |
|---|---|
| Widening scope by "correcting" a pattern without approval | The replacement goes through `decideNewEntry`, the rule of a new entry, with step-up; tests cover a widening and a narrowing in Strict |
| Coverage gap during the correction | The old entry stays in effect until the replacement is in effect; both change in one transaction |
| Replacing another tenant's entry | Tenant-scoped read (404); composite `(tenant_id, id)` foreign keys keep both links inside one tenant |
| Partial write (new entry saved, old not retired, or the reverse) | `SaveReplacement` writes both rows in one transaction |
| Changing a scan zone through scope rights | The zone changes only through the scan zone API with `sensors:zones:write`; zone names and ranges are shown only with `sensors:zones:read` |
| Resurrecting a replaced entry | A superseded entry cannot be activated, deactivated, widened or replaced again |

## Key files

| File | What |
|---|---|
| `pkg/domain/scope/replace.go` | Superseded status, links, coverage change |
| `internal/app/scope/replace.go` | `ReplaceTarget`, `PreviewReplaceTarget`, retirement on approval, zone note |
| `internal/infra/postgres/scope_target_repository.go` | `SaveReplacement`, `PendingReplacement` |
| `internal/infra/http/handler/scope_replace_handler.go` | Routes, response, audit |
| `migrations/20261106174420_scope_entry_replace.up.sql` | Columns, status, unique index |
| `web/src/features/scope/components/scope-replace-pattern.tsx` | The Replace pattern section of the Edit scope entry dialog |
