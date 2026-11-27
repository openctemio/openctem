### Changed: Scan approval follows the settings page pattern (redesign branch)

- `/settings/scanning/scan-approval` is drawn with the shared settings parts: Mode and Approval rules sections.
- The mode is saved through the page's save bar instead of a Save button in the section; the reason dialog and the
  re-authentication the API asks for are unchanged. Presets, Add rule, Try the rules, reorder, turn off and remove
  still apply one change at a time, each after a reason.
- Loading and a failed load look as on every settings page; view only for members who are neither owner nor
  administrator, as before. Permissions and every API call are unchanged.
- Docs: none (the page keeps its functions; the look is described in web/docs/ui-style-contract.md, "Settings pages")
