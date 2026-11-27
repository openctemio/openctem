### Added: change a filter's operator and values from its chip on Findings

- The text of a filter chip on Findings is a button: it opens the editor Add filter shows for that field, on the chip's own operator and values, anchored to the chip (a bottom sheet on a phone). Apply rewrites the filter in the address in its place; Escape or a click outside changes nothing, and focus returns to the chip.
- Changing between two operators of one kind ("is" and "is not", "≥" and "≤") keeps the values that were entered, in Add filter too.
- Chips of the open saved view stay locked, and unknown filters stay as they are.
- Docs: web/docs/findings-list.md
