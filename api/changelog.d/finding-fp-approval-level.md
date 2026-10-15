### Security: per-organization false-positive approval level

- New setting `finding_approvals.fp_approval`: `all` (default, unchanged: a
  second person approves every false positive), `high_and_above` (a second
  person only for a critical or high finding, KEV, P0/P1, a validated exploit,
  or a crown-jewel or internet-exposed asset) or `off` (one person may decide
  any false positive). An accepted risk always needs a second person.
- Deciding alone needs `findings:approve` and the finding in the caller's data
  scope; the closure reason (VEX-aligned) and a note stay required. The
  request is written approved with `single_person`, the finding moves at once,
  in one transaction with its timeline entry, audited
  `finding_approval.single_person_decided`.
- A false positive one person decided (alone, or the sole member's own) gets a
  review flag (`material_change_single_person`) when its severity rises, it is
  added to KEV, or new evidence is attached (database triggers on every write
  path). `second_look_percent` (0-10, default 0) flags a random share for a
  second look (`second_look_sample`).
- Changing the level needs an owner or administrator with `settings:write`
  and a recent re-authentication,
  is audited with before/after and the approvers are told. **Lowering takes
  effect 24 hours later** (`pending_fp_approval`, `pending_fp_approval_at`);
  raising is immediate and cancels a pending lowering. Lowering the
  second-look share waits 24 hours the same way.
- The single-person write re-reads the level and the finding's facts inside
  its transaction (the finding locked); a level raised or a finding made
  material in between turns it into a normal request for a second person.
- `GET /api/v1/findings/{id}/approvals/policy` says how a false positive on
  that finding is decided now (for the request dialog).
- Migrations `002521`-`002523` (`finding_approval_single_person`,
  `finding_single_person_fp_review`, `finding_decision_review_reason_validate`):
  a boolean with a constant default; two triggers (short lock, no scan; the
  findings trigger fires only when a false positive's severity or KEV flag
  changes); the widened review-reason check is added `NOT VALID` and validated
  separately.
- Depends on the closure reasons of #2277.
