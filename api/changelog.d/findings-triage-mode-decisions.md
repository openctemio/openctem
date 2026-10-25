### Added: triage mode add to task, retest, undo, receipt and AI suggestion

- Triage mode gains add to task (`m`, with the move offer when the finding is already in an active task), retest (`r`) and undo (`u`, up to 10 decisions). Undo uses the inverse request with its own permission check: a sent false-positive or acceptance request is canceled (kept on record), an assignment returns to the previous assignee, and a decision the lifecycle cannot reverse (such as a confirm) says so.
- Exit after decisions shows the session's receipt first.
- With the AI triage module, the finding's latest AI triage shows as an advisory card. "Apply suggestion" only fills the false-positive request form; a person sends it.
