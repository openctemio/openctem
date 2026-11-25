### Fixed: phone card fields, owners and the last cut labels are no longer lost to an ellipsis

- A list's phone card shows each field's label and value in full: the value sits beside its label when both fit, else under it, and wraps ("Last active", "about 2 months ago", an IP address). A very long value stops after three lines with its full text as a tooltip. A card's subtitle takes up to two lines, and a long state chip wraps on its own line.
- An asset's owner, or "No owner", wraps in the table instead of being cut.
- Wrap instead of being cut: file names next to "Choose a file", exposure category buttons, asset source names, proxy sources, posture categories, CTEM loop stage names, a workflow's name and canvas hint, list headings, filter panel options, organization names, role names and descriptions, team, asset, checklist and template names in pickers, task titles when adding tasks to a campaign, and template reference links.
- Kept on one line with the full text as a tooltip: finding titles and targets, asset names, the assignee, the watchers summary, copyable IDs, chips, locked filter chips and toolbar select values.
- Docs: web/docs/ui-style-contract.md (Tables: the automatic phone card)
