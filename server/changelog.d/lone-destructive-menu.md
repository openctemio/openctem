### Changed: a lone destructive action stays behind the "⋯" trigger (redesign branch)

- A menu with one non-destructive item that has an icon still renders as that button. A lone destructive item
  (Delete, Remove, Revoke, Disable) no longer does: it stays behind the "⋯" trigger, so a row never shows a bare
  destructive button that can be mis-tapped, and the development-time one-item error does not fire for it.
- Compensating controls: Link assets and Test join Delete in the row's one "⋯" menu. The typed-name confirmation is unchanged.
- Docs: web/docs/findings-list.md ("More menu")
