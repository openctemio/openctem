### Added: the asset page has its actions, findings, technologies, key facts and risk (redesign branch)

- The asset page header has one main action chosen by the asset's state: Scan now when scans may reach the
  asset now, otherwise Edit. More holds Edit, the lifecycle snooze (presets, a custom number of days, clear),
  Mark out of scope and Archive (with Undo), then the links. Each opens the dialog the inventory and its drawer
  already use, behind the same permission; the snooze now needs assets:write in the menu, as the API does.
- New tabs: Findings (the asset's open findings, with their count) and Technologies (when probes found any).
  Overview starts with the key facts and the risk summary (score, open findings by severity, why this score).
- Owner roles ("Primary", "Stakeholder", …) and their hints, and the type of each related asset, are now
  translated.

Docs: none (behaviour described in the pull request; no settings or API change)
