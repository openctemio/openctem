### Fixed: table cells and headers no longer hide their meaning behind an ellipsis

- A table value that is not the row's name (a description, an owner, an e-mail, a source, scopes, a duration, a reason) wraps to two lines instead of ending in an ellipsis on one; a longer one keeps its full text as a tooltip. An e-mail or a host name wraps only at its separators.
- A column header wraps instead of being cut ("Risk removed", "Chấp nhận rủi ro kết thúc").
- Dates fit their column in Vietnamese ("25 thg 11, 2026"), a scan run's start time fits in full, and a relative time wraps in a narrow column instead of being cut ("12 minutes ago").
- The asset of an external-surface row and the name of a scan profile are the row's name: a long one ends in an ellipsis with its full text as a tooltip.
- Docs: web/docs/ui-style-contract.md (Tables: what may end in an ellipsis)
