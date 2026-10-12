### Behaviour change: scan workflows live under Scans; automations at /automations

- The console's Scans page has three route tabs: **Scans** (`/scans`), **Runs** (`/scans/runs`) and **Workflows** (`/scans/workflows`). The workflow editor is `/scans/workflows/{id}`. Each tab is its own page with one list, so links to a page of runs or workflows are plain URLs.
- Scan workflows left Mobilization: the "Scan Pipelines" sidebar row is gone, and the scan workflow list drops its "Recent runs" and "Visual builder" tabs (the Runs tab and the editor cover them). Creating a workflow needs `scans:workflows:write`.
- Event automation is **Mobilization > Automations** at `/automations`.
- The old `/pipelines`, `/pipelines/{id}/builder`, `/workflows` and `/scans?tab=runs` pages are removed with no redirect. The command palette still finds the Workflows tab when you search "pipeline" or "builder".
- **Upgrade note:** update bookmarks to the new paths.
