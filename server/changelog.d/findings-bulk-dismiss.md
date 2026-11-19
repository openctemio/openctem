### Added: dismiss findings in bulk, with a preview and undo

- `POST /api/v1/findings/bulk-dismissals/preview`, `POST /api/v1/findings/bulk-dismissals` and
  `POST /api/v1/findings/bulk-dismissals/{id}/reopen` (`findings:bulk_update` and `findings:write`): mark up to
  500 selected findings (by ids, or by the list's filter with the confirmed count) a false positive or accept
  their risk. Each finding follows the same approval policy as a single request: the ones the person may decide
  alone are applied now (each with its own timeline entry and audit row), the rest becomes one approval group
  (source type `selection`), and the skipped ones say why.
- Guardrails: more than 25 decided alone, in one call or across the calls of the last hour, needs a recent re-authentication; at most 1,000 decided alone per
  person per 24 hours (the rest goes to approval); a bulk audit event (`finding.bulk_dismissed`, high severity
  and an immediate notice to the owners above 100 decided alone); a retry with the same idempotency key returns
  the first result. Undo by its creator within 24 hours reopens the findings it decided alone and cancels its
  pending group; nothing is deleted.
- New error code: `BULK_DISMISS_TOO_LARGE` (400, with the count). A key reused with another request answers
  the existing `IDEMPOTENCY_KEY_REUSED` (422), as bulk-by-filter does.
- Second look: a bulk that decides 10 or more findings alone, with the organization's second-look share above
  0, always gets at least one second look (one decided finding chosen at random when the per-finding sampling
  raised none).
- The audit rows of a bulk are written even when the client disconnects during the apply; an undo while the apply is still running answers 409 (retry it); the requester is recorded by the same identity the approve paths compare with.
- Known limit: undo reopens every finding to `confirmed`, whatever status it had before the dismissal.
- Known limit: an apply of 500 decided alone takes about 17 seconds (the findings are written one at a time).
  A batched write path is a planned follow-up.
- Migration 20261119095221 (`finding_bulk_dismissals`, and `selection` added to the approval group source
  types). Its down migration stops while a `selection` group exists, so no decision record is deleted.
- Docs: server/docs/architecture/findings-bulk-by-filter.md#bulk-dismiss

### Behaviour change: the note is optional when you decide alone on a finding that is not serious

- A false positive or accepted risk that you decide alone under the organization's approval level, on a
  finding that is not serious (not critical or high, KEV, P0/P1, a validated exploit, a crown-jewel or
  internet-exposed asset), no longer needs a note: the reason code is enough. A request that waits for another
  person, every group exception, and any serious finding still need a note of the tier's length. The reason
  code is always required. Applies to `POST /api/v1/findings/{id}/approvals` and bulk dismiss.
- Docs: server/docs/architecture/finding-status-lifecycle.md (When a note is required)
