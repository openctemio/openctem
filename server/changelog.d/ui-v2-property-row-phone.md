### Fixed: a phone property row with a control is 44 px like the others (redesign branch)

- A record's property row on a phone held a 36 px control (a status or assignee picker, the watchers row) in
  a 49 px line; it is now 44 px, the height of every other row. A value of several lines keeps its padding.

Docs: web/docs/ui-style-contract.md
