### Changed: an empty list's action is an outline button beside the page's main action

- A list with no rows showed two filled buttons: the page's main action in the header and the empty state's own (for example "New group" twice on Asset groups, "New workflow" and "Create workflow" on Automations). The empty state's action is now filled only when no other filled button is on the screen, and an outline button otherwise; a page whose header has no main action in that state keeps it filled (every list and empty state).
- Docs: web/docs/ui-style-contract.md (empty state)
