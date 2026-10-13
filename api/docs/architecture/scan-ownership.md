# Scan ownership

A scan's owner is `scans.created_by`: the member who created, cloned,
imported or saved it, or the administrator who took it over. A **scheduled
run acts as the owner**: its targets are checked against the owner's act
scope, and it is never run as the unrestricted system (research 21b H2/H3,
RFC-050 W2, #1157).

## States

| `owner_state` | Meaning | Scheduled run |
|---|---|---|
| `ok` | The owner is an active member | Runs |
| `missing` | No owner: the account that created the scan was deleted (`created_by` is `ON DELETE SET NULL`), or the scan predates owner attribution | Refused with `SCAN_HAS_NO_OWNER`; the scan is paused |
| `inactive` | The owner is disabled or left the organization | Refused with `SCAN_OWNER_INACTIVE`; the scan is paused |

The scan detail (`GET /api/v1/scans/{id}`) reports all three; lists report
`missing` only (no membership lookup per row). A run a member starts by hand
("Run now") acts as that member and is unaffected.

## What happens when a scheduled scan loses its owner

1. At its next due run the trigger gate refuses the run (a blocked run with
   the refusal code), pauses the scan and clears `next_run_at`.
2. Every active owner and administrator of the organization gets one in-app
   notification (type `scan_failed`, linking to the scan). It is sent only
   on the active → paused transition: a paused scan has no due runs, so
   nothing repeats.
3. Resuming the scan (`POST /scans/{id}/activate`, bulk activate) is refused
   with the same code while the owner is missing or inactive: it would only
   be paused again.
4. An administrator opens the scan, takes ownership, then resumes it.

## Take ownership

`POST /api/v1/scans/{id}/take-ownership`: owners and administrators only
(`RequireAdmin` + `scans:write`; an API key is never an administrator).

- Allowed only when the owner is `missing` or `inactive`; an active owner
  keeps the scan (`409 SCAN_OWNER_ACTIVE`). A failed membership lookup also
  refuses.
- The caller's act scope must cover the scan's direct targets, as on a clone:
  the scan's scheduled runs will act with the caller's scope.
- Tenant-scoped; another organization's scan is `404`.
- A compare-and-swap on the previous owner (`ScanRepository.SetOwner`): two
  administrators at once cannot both win (`409 SCAN_OWNER_CHANGED`).
- Audited as `scan_config.owner_taken` with the previous state and owner.
- The scan is not resumed: resuming stays an explicit step.

## Creation paths

Every path that saves a scan sets the acting member as owner: create, clone,
import, quick scan and "Save as scan". A scheduled scan with no owner (a call
without a user, for example an API key that belongs to no user) is refused
at creation with `SCAN_OWNER_REQUIRED`. Automatic enrichment scans are
ad-hoc, run once by the platform and are never scheduled.

## Where things live

| Piece | Code |
|---|---|
| Trigger gate, pause, notice | `internal/app/scan/trigger.go` (`refuseOwnerlessSchedule`), `internal/app/scan/owner.go` |
| Take ownership, owner state | `internal/app/scan/owner.go`; `internal/infra/postgres/scan_repository.go` (`SetOwner`) |
| Route and response | `internal/infra/http/routes/scanning.go`, `internal/infra/http/handler/scan_handler.go` (`owner_state`, `TakeScanOwnership`) |
| Web | `web/src/features/scans/components/scan-owner-banner.tsx` |
