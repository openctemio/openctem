### Fixed: the Automations canvas shows and saves only what runs

- The visual builder no longer opens on a hard-coded demo graph. A new workflow starts with one manual trigger, and a stored workflow opens as saved.
- Selecting a step opens an inspector for its settings: the trigger, the action or the notification channel, a saved scan for "Trigger scan", tags as a list, and JSON for other settings.
- The API refuses a workflow graph with a cycle, a step no trigger reaches, an edge into a trigger or a condition edge without a yes/no branch (400, `WORKFLOW_GRAPH_CYCLE`, `WORKFLOW_GRAPH_UNREACHABLE` or `WORKFLOW_GRAPH_EDGE`). It refuses before anything is written, so a bad save no longer leaves the stored graph half-replaced. The canvas refuses the same connections while you drag and lists the steps that are not connected.
- The `run_script` action, which always failed, is refused on write (400 `UNSUPPORTED_WORKFLOW_FEATURE`) and is no longer offered. The `finding_status_changed` trigger, which the finding service already fires, is now accepted and offered.
- Workflow validation errors carry their code in the response `code` field.
