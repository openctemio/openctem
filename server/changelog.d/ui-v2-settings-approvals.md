### Changed: Settings > Approvals replaces Finding approvals, with one save bar (redesign branch)

- `/settings/approvals` shows the approval levels (false positive, risk acceptance, second look, backup contact) and
  the approval policy (who approves, security pool and exclusions, limits and deadlines, material changes) as
  sections of one page. `/settings/finding-approvals` redirects permanently to it; the settings rail entry is
  "Approvals" in Findings & assets.
- One save bar saves both parts in one request to the same endpoint: the body is the union of the fields each part
  sent before (the changed level fields, and the whole policy when it changed). A refused save keeps the changes.
- Scan approval keeps its own page and permission; the Approvals page links to it for whoever may open it.
- Permissions (`settings:read` to open, an owner or administrator with `settings:write` and a recent sign-in to
  save), the owner-only lowering rule, the 24-hour wait and the cancel of a waiting lowering are unchanged.
- Docs: none (the page keeps its functions; the stored notification link reaches it through the redirect)
