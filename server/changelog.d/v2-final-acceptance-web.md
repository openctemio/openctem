### Fixed: final acceptance fixes in the web console (meaning no longer cut, reasons shown, tables kept short)

- A needs-attention queue shows its reason line from 768 px as the header's last line instead of hiding it in the reason menu below 1280 px.
- The error panel no longer prints the request id; "Copy request ID" copies it.
- A phone card gives a field whose label or value its half of the line would cut ("18 minutes a…") the whole line, as it already did for a chip.
- The header search is 320 px wide from 1280 to 1535 px, so the breadcrumb beside it keeps its names.
- Scan runs: "Triggered by" has room for a whole address on a wide screen; asset activity: a long reason takes at most two lines with its full text as a tooltip, so rows stay short.
- Notifications keep the line breaks of their text instead of return marks.
- Labels and sentences wrap instead of ending in an ellipsis: the file picker's file name, ATT&CK tactic names, asset source names, proxy scanner sources, exposure type tiles and CTEM loop stage names. Names that may still be cut (dashboard items, finding titles and targets, an assignee) carry their full text as a tooltip.
- The inventory's hidden-names chip reads "N names hidden"; its tooltip says why.
- Docs: none (layout and wording of existing screens only)
