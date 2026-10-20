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
