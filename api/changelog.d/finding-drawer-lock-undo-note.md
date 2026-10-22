### Fixed: the finding drawer locks what the page locks, and Undo works and asks for its note

- The finding drawer now locks status, severity and assignee for pentest, bug bounty, red team and manual findings, the same rule as the finding page (one shared helper). Before, the drawer let you change them and the API refused after an optimistic update.
- Undo after a status change now reverts to the previous status (the toast kept a stale copy of the status and treated the undo as already done). When the previous status needs a note (fix applied, resolved), Undo opens the note dialog instead of sending no note.
