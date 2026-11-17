### Fixed: a list's toolbar keeps its place when a value is chosen, a row is selected or the rows load

- A filter token that can be cleared ("Status: Expired") keeps the room of its clear button while nothing is chosen, so choosing a value no longer widens it and pushes the controls after it (Certificates, Technologies, Exposures, Emerging threats).
- A table without a bulk bar says "N of M selected" under its rows, in the pager's line, instead of in the toolbar's end, where it moved the buttons beside it (Vulnerabilities).
- Findings shows its real toolbar and chips row over placeholder rows while the first page loads, and a placeholder of the title row's own height before that, so the list no longer jumps when the rows arrive.
- Under Compliance, the benchmarks block sits under the chips row and above the rows instead of above the title row, and folds to its heading: the title row and the toolbar no longer move when it loads.
- On a phone the second toolbar line keeps the chips at its start and the filter tokens at its end, beside the icon actions, whether or not a chip shows: adding the first filter no longer moves the tokens (every list).
- Docs: web/docs/ui-style-contract.md (list state filter), web/docs/findings-list.md ("First load", phone toolbar)
