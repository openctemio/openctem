### Changed: the web console offers the status moves the API allows

- The finding status menu (drawer, properties, remediation task) lists the moves from `GET /findings/{id}/transitions` for the signed-in user. An allowed move can be chosen; a blocked one is shown disabled with the reason, for example "Needs the findings:verify permission" or "Only the assignee, an assigned group member or the asset owner can claim a fix". The menu loads its moves when it opens.
- A bulk status change first runs the dry run (`POST /findings/transitions:evaluate`), sends only the findings that may move, and reports how many cannot move and why.
- The console's own copy of the transition map (`STATUS_TRANSITIONS`, `AUTOMATED_STATUSES`, `PENTEST_STATUSES`) is removed. The API's transition engine is the only copy of the rules.
