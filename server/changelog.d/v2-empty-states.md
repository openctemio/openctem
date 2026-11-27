### Changed: empty lists and pages show a short, useful empty state

- The shared empty state is sized to its content (small icon, title, one line, at most one action) instead of a tall mostly blank box, and inside a card, table or list frame it no longer draws a second frame. Queues and the default table empty body use it too, so every empty list looks the same.
- A list filtered to nothing says "No results" with Clear filters instead of the first-use text.
- An empty state no longer repeats the page header's main button (automations, control tests, programs, asset groups, scan workflows, service accounts, ticketing, SIEM, source code connections, scanner templates, scan profiles, credentials, capabilities, pentest templates and more). Empty states that pointed elsewhere in words now link there (business impact, code, misconfiguration and secret exposures, program maturity, detections, tool settings). Reported sensor products sit inside the empty state as one-click suggestions.
- Status labels such as Active, In effect and Pass are outline badges instead of filled dark pills, so the page's main button stays the one filled control; Scan now in the asset sheet and New pool on proxy settings are outline buttons beside the main action.
- Docs: web/docs/ui-style-contract.md ("Empty")
