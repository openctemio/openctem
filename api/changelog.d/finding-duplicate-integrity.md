### Security: a duplicate always names the finding it duplicates

- `PATCH /api/v1/findings/{id}/status`, `POST /api/v1/findings/bulk/status` and
  the workflow `update_status` action refuse `duplicate` with a 400: a
  duplicate is made with `POST /api/v1/findings/{id}/duplicates`, which names
  the canonical finding and checks `findings:triage` (and `findings:approve`
  when a side carries a decision). Before, a holder of `findings:status` could
  close a finding as a duplicate of nothing, bypassing both checks.
- The drawer's status control no longer offers Duplicate (use Mark duplicate).
- Migration `002151` adds the CHECK `chk_findings_duplicate_has_target`. It
  first reopens every duplicate without `duplicate_of` to `confirmed`, with a
  timeline entry (reason `duplicate_link_missing`). Deleting a canonical
  finding now reopens its duplicates the same way instead of failing.
