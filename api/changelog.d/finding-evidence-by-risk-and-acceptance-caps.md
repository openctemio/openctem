### Changed: closing a finding needs evidence in proportion to risk; risk acceptance is capped by priority

- A person resolving a critical, P0 or known-exploited (KEV) finding needs a
  retest that confirmed the fix, or the verification checklist completed by a
  second person. A high or P1 finding needs the verification checklist (or a
  confirming retest). Medium and low findings close with a note, as before.
  The status menu and the bulk preview show the reason a resolve is blocked
  (`evidence_required`, `checklist_required`); `PATCH /status` answers 400.
- An accepted risk may last at most 30 days for P0 or KEV, 90 for P1, 180 for
  P2 and 365 for P3. A request with no end gets 90 days or the cap when
  shorter; an end past the cap is refused, never shortened. The finding
  response carries `max_acceptance_days` and the approval dialog limits its
  date to it.
- Migrations `002461_acceptance_cap_review` and
  `002462_acceptance_cap_review_validate`: accepted findings whose end is past
  the new cap are flagged for review (`acceptance_exceeds_cap`, with a timeline
  entry), not shortened; the migration reports how many.
