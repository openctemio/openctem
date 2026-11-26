### Changed: Settings > Approvals is a short list of approval types, each edited on demand (redesign branch)

- `/settings/approvals` shows one row per approval type (false positives, accepted risks, suppression rules,
  scans) and per shared rule (approvers, deadline and high risk, backup contact), each saying in plain words what
  is set, for example "A second person approves every one. Critical: Two approvers". The row's Change button
  opens its editor in a dialog (a bottom sheet on a phone); a person without `settings:write` gets View, the same
  editor with nothing to save. On a 390 px phone the page drops from about 4,600 px to the rows alone.
- Each editor saves its own fields with one request to the same endpoint (the changed level fields, and the whole
  policy when it changed). A refused save keeps the editor open with the draft and the server's reason.
- Lowered protections that wait their 24 hours are listed together above the rows, with one "Cancel the waiting
  changes" (the API always dropped every waiting lowering at once). "What the tiers mean" stays folded.
- The scans row says the scan approval mode in force and opens its own page, still for whoever may open it.
- Unchanged: `settings:read` to open, an owner or administrator with `settings:write` and a recent sign-in to save,
  lowering a level or relaxing the policy owner only and 24 hours later, raising at once, the audit entry and the
  notice to approvers. Settings search anchors now point at the rows (`#false-positives`, `#accepted-risks`,
  `#suppression-rules`, `#security-pool`, `#approval-limits`).
- Docs: https://docs.openctem.io/user-guide/10-settings-and-integrations/ (the Approvals text of docs PR #316 says "one page with one
  save bar" and "Approval policy section": to be updated to the rows and editors)
