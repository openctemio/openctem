### Changed: Tool defaults and Scanner content follow the settings page pattern (redesign branch)

- `/settings/scanning/tool-defaults` and `/settings/scanning/content` are drawn with the shared settings parts:
  title, the note on where values come from, the view-only note, loading and failed-load states.
- Scanner content saves through the save bar (shown only while something changed, with what changed, Discard,
  Ctrl/Cmd+S and a prompt before leaving) instead of a Save button in the page header. "Apply to sensors now" is a
  switch in the Refresh schedule section. Field errors are tied to their fields.
- Tool defaults keep their per-tool save. Permissions and every API call are unchanged.
- Docs: none (the pages keep their functions; the look is described in web/docs/ui-style-contract.md, "Settings pages")
