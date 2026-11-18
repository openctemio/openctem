### Fixed: list toolbar: Add filter answers clicks again, and a phone's end controls stay at the end

- A list whose filter tokens are all chips (Assets on a desktop) left only the icon-only Add filter in its tokens group. The empty-group check measured the icon's strokes, which have no area, called the group empty and took clicks away from it: Add filter did nothing. An icon now counts by its own box.
- On a phone, with the tokens group out of the flow, the end group (Views, Display, Export) sat at the start of its line and jumped to the end when the first filter chip appeared or Query mode was switched on. It now keeps its place at the end.
- Docs: web/docs/ui-style-contract.md (list toolbar)
