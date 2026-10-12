### Added: scan workflow drafts and publish

- The builder saves a draft, and saving never fails because of a problem in
  it: the layout and the edits are kept even when a pinned tool is missing.
  The draft autosaves shortly after each change, and leaving with unsaved
  changes asks first.
- Every issue of the draft is listed in a panel under the header and on each
  node, split into blocking issues and warnings, each with how to fix it.
  Choosing an issue selects its step.
- **Publish** makes the draft the steps runs use. It is refused (422 with
  every issue) while the draft has a blocking issue. Steps keep their ids
  and run history, the version moves on, and the draft is removed.
  **Discard draft** goes back to the published steps.
- Badges: Unsaved, Draft, Published vN.
- API: `GET`/`PUT`/`DELETE /api/v1/scan-workflows/{id}/draft` and
  `POST /api/v1/scan-workflows/{id}/publish`, gated like the workflow reads
  and writes. Migration 001329 adds `draft`, `draft_issues` and
  `draft_updated_at` to `scan_workflows`.
