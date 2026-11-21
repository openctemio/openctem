### Changed: queue cards on a phone are balanced, with the decision at the end

- On a phone the cards of the queues (approval requests, scan approvals, ready to close, recently closed, My Work findings, duplicate assets, relationship suggestions) put the item's state at the end of the title line and the decision at the end of one line of key facts: Approve with More, whose first item is Reject. A card with nothing to decide ends with a chevron to the item. The reason stays at two lines.
- The approval requests page no longer shows Refresh alone on a line above the list: it sits at the end of the list's toolbar, and an empty title row takes no room.
- The layout-break browser check (spec 75) now fails a phone card whose content stops short of its end and a title row line whose start is empty.
- Docs: web/docs/ui-style-contract.md (Queues). No user guide change: the guides do not describe the phone cards.
