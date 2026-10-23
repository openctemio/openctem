### Fixed: Dashboard editor and dashboards list

- Cancel in the dashboard editor asks before discarding unsaved changes, and leaving the page while there are changes asks the browser to confirm.
- Undo in the "widget removed" message now puts back exactly the removed widget, even after other changes.
- The widget configuration panel no longer requests a preview for figures it already has, and Apply never stores a preview that belongs to an earlier draft.
- A widget target shows its unit, is limited to 100 for percentages, and an empty value disables Apply instead of becoming 0. Section headings are in sentence case, and the "Del" shortcut is translated.
- Dashboards list: using a template twice creates a numbered copy instead of failing, the edit form is addressed by `?edit=<id>` so Back works, each dashboard has a Customize action, and the page follows the style rules (one default button, no cards in the form, no toasts for visible changes).
