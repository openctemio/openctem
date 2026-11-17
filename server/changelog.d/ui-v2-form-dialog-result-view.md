### Changed: form dialogs can show a result view with one action (redesign branch)

- `FormDialog` takes `cancelLabel={null}` to leave Cancel out, for a result view inside the same dialog whose one
  action (Done) closes it; X and Escape still close it.
- Docs: web/docs/ui-style-contract.md ("Form dialog")
