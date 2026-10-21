### Security: the verification checklist now records who completed it, and is tenant, data-scope and audit controlled

- `PUT /api/v1/verification-checklists/{findingId}` never recorded `completed_by` / `completed_at`, so the second-person evidence rule for critical, P0 and KEV findings (and the checklist rule for high findings) could not be met by anyone. The edit that leaves every required item ticked now records the caller as the completer; unticking a required item clears the record.
- The route now applies the caller's data scope (an out-of-scope finding is a 404, like another tenant's), accepts edits only on open findings (new to `fix_applied`; 400 otherwise) and caps the notes at 4000 characters.
- Every edit writes the audit action `finding.verification_checklist_updated` (changed items, completion state; not the notes text).
- `GET /api/v1/verification-checklists/{findingId}` no longer creates a row: it is read-only and returns an empty, incomplete checklist when none exists.
