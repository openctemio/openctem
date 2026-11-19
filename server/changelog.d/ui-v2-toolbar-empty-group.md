### Fixed: on a phone, a list toolbar group with nothing to show takes no line

- On a phone the list toolbar kept a group whose controls were all hidden at that width (the Display menu, or filter tokens moved into the Filters sheet) on a wrapped line of its own. The first filter chip then took that line, so adding a filter moved the list by 36 px instead of one row and its gap. Such a group now leaves the flow until one of its controls is drawn again (every list toolbar).
- Docs: web/docs/ui-style-contract.md (list toolbar)
