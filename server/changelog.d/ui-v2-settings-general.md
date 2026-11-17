### Changed: Settings > General is one page of sections with one save bar (redesign branch)

- `/settings/general` shows Organization information, File storage, Dashboard data and the owner's Danger zone as
  sections of one page instead of three tabs. Links with `?tab=storage` or `?tab=dashboard-data` land on that section.
- One save bar saves the organization form and the file storage form together, lists what changed and keeps the
  changes of a part whose save failed. The storage keys are masked fields that never show a stored value.
- The Dashboard data section reads its state when it comes into view (or a link lands on it), so the page loads
  with no more requests than before.
- Permissions, validation, the typed confirmation for deleting the organization and every API call are unchanged.
- Docs: none (the page keeps its functions; the look is described in web/docs/ui-style-contract.md, "Settings pages")
