### Fixed: a list's toolbar keeps its place when a value is chosen, a row is selected or the rows load

- A filter token that can be cleared ("Status: Expired") keeps the room of its clear button while nothing is chosen, so choosing a value no longer widens it and pushes the controls after it (Certificates, Technologies, Exposures, Emerging threats).
- A table without a bulk bar says "N of M selected" under its rows, in the pager's line, instead of in the toolbar's end, where it moved the buttons beside it (Vulnerabilities).
- Findings shows its real toolbar and chips row over placeholder rows while the first page loads, and a placeholder of the title row's own height before that, so the list no longer jumps when the rows arrive.
- Under Compliance, the benchmarks block sits under the chips row and above the rows instead of above the title row, and folds to its heading: the title row and the toolbar no longer move when it loads.
- On a phone the second toolbar line keeps the chips at its start and the filter tokens at its end, beside the icon actions, whether or not a chip shows: adding the first filter no longer moves the tokens (every list).
- Sensors holds the fleet bar and its legend line while the fleet loads, so the title row and the list under the health strip no longer drop when the sensors arrive.
- On a phone a labelled toolbar end action (Export CSV on Technologies, Certificates and Exposures) is a named icon, so the filter tokens and the Clear filters button keep their room on the second line.
- On a phone card, a field that is only a switch (Enabled on Workflows) reads "On" or "Off" beside it, so the card never shows a label without a value.
- Docs: web/docs/ui-style-contract.md (list state filter, toolbar end actions, a switch on a phone card), web/docs/ui/shared-kit.md (ToolbarAction), web/docs/findings-list.md ("First load", phone toolbar)
