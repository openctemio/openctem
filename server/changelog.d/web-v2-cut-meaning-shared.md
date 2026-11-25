### Fixed: labels, chosen values and column headers are no longer cut by an ellipsis

- A headline number's label (the metric strip above a list) wraps instead of ending in an ellipsis or a two-line clamp, so "mất kết nối, SDK, heartbeat cũ" reads in full at every width; the numbers of a row stay on one line.
- A select field shows its chosen value in full: a long value wraps and the field grows from its usual height, instead of "Mọi mức rủi…".
- A table's column header wraps to a second line instead of being cut ("Mức độ quan trọng").
- The Sensors fleet tiles show their detail line in full.
- A row's name that ends in an ellipsis in a table or a phone card shows its full text as a tooltip.
- Docs: web/docs/ui-style-contract.md (layout rule, with the layout matrix change)
