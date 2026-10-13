### Behaviour change: a scheduled scan without an active owner is paused, and an administrator takes ownership

- A scheduled scan whose owner is missing (the account was deleted) is now paused at its first refused run (`SCAN_HAS_NO_OWNER`), like one whose owner left (`SCAN_OWNER_INACTIVE`); before, it stayed active and was refused at every due run. The organization's owners and administrators get one in-app notice per scan.
- Resuming such a scan is refused until it has an active owner. New: `POST /api/v1/scans/{id}/take-ownership` (owners and administrators; the caller's act scope must cover the scan's targets; audited as `scan_config.owner_taken`). The scan response has `owner_state` (`ok`, `missing`, `inactive`) and the scan page shows a banner with a "Take ownership" button.
- A scheduled scan can no longer be created without an owner (`SCAN_OWNER_REQUIRED`).
- **Upgrade note:** scheduled scans that are already ownerless pause at their next due run and notify the administrators; take ownership and resume the ones to keep.
