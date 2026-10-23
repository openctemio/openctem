### Fixed: findings list speaks the app language and stops claiming a copy that failed
- Bulk assign and status results are translated with proper plurals ("Assigned 1 finding").
- Copy ID and Copy link report a refused clipboard instead of "copied", in the list and the finding drawer.
- The findings drawer no longer captures Ctrl/Cmd+C; the activity panel's `C` key opens the comment box.
- Created and KEV due dates use the app locale; source categories in the filter panel are translated.
- KEV, EPSS and attack-path chips use theme tokens at a readable size, and the path chip says "Path" instead of relying on colour.
- Phone cards lead with the priority class; a finding with no asset name shows "Unnamed asset" instead of an id fragment.
- Refresh no longer toasts; the filter panel is a flat bordered panel.
- On a phone the Awaiting verification button uses a short label, so the view title stays readable.
