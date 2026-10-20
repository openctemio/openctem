# Managed scans

A **managed scan** is a scan the platform owns. Continuous coverage
(RFC-093) and automatic enrichment carry their runs on managed scans, so
every run has a scan to belong to, but nobody created them and nobody edits
them as a scan.

## Identity

`scans.managed_by` (`coverage`, `enrichment`) and `scans.managed_key`
identify a managed scan; both are `NULL` on a person's scan.

| `managed_by` | `managed_key` | Scan |
|---|---|---|
| `coverage` | the capability, e.g. `probe.http` | one per tenant and capability, reused by every batch |
| `enrichment` | the scan's own id | one per enrichment batch |

A partial unique index `scans_managed_key (tenant_id, managed_by, managed_key)`
keeps one managed scan per tenant and key. The planner finds its scan by
`(managed_by, managed_key)` through `scan.Repository.GetManaged`, never by
name: a member's scan that happens to carry the name `Continuous coverage:
probe.http` is left alone (its targets, owner and schedule are untouched) and
coverage creates its own managed scan under another name
(`... (platform)`).

Creating a managed scan is audited as `scan_config.managed_created`.

## Origin

`GET /api/v1/scans` takes `origin=user|system`. `system` lists managed scans
(they are ad hoc, so the default list hides them); `user` lists scans that no
policy owns. Without `origin` nothing changes.

## Migration

`scans.managed_by` / `managed_key` are nullable columns without a default (no
table rewrite). The backfill marks only **ownerless** rows (`created_by IS
NULL`): scans tagged `auto-coverage` with the coverage name, and scans tagged
`auto-enrichment`. A scan a person created or took over is never marked, even
when it carries the platform's name or tag.

## Read-only through the scan API

A managed scan is changed only through the policy that owns it. These calls
are refused with `409 SCAN_MANAGED_BY_POLICY` and change nothing:

| Call | Refused |
|---|---|
| `PUT /scans/{id}` (any field, schedule included) | yes |
| `DELETE /scans/{id}`, `POST /scans/bulk/delete` | yes |
| `POST /scans/{id}/pause`, `/activate`, `/disable` and the bulk forms | yes |
| `POST /scans/{id}/take-ownership` | yes |
| `POST /scans/{id}/save` (promote to a configuration) | yes |
| `POST /scans/{id}/trigger` ("Run now"), an approved or emergency run of a member, an automation's `trigger_scan` step | yes |
| `POST /scans/{id}/clone` | allowed: the copy is an ordinary scan owned by the caller, without `managed_by` and without the platform's marker tag |

The policy's own runs (the coverage planner, the retry of a failed run) are
not affected. A managed scan has no owner: `owner_state` is `managed` and
`managed_by` names the policy, so a client shows it as a platform scan, not as
an orphaned one. `GET /scans/{id}` and the run history stay readable with
`scans:read`.

Threat model: before this, any member with `scans:write` could edit, pause,
schedule or delete a coverage scan, or (administrators) take it over so that
every later coverage run acted as them. Cross-tenant ids resolve to 404 as
for any scan.
