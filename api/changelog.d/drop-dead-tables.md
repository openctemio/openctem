### Removed: tool run statistics that were always zero, and two tables nothing wrote (migration 001482)

- `GET /api/v1/tools` and `GET /api/v1/tools/{id}` no longer accept `include=stats` or `days`: the statistics came from `tool_executions`, which no code path ever wrote, so every tool always showed zero runs. `include=stats` now answers 400 like any unknown include. The web console never requested it.
- Migration 001482 drops `tool_executions` and `component_licenses` (the shared component-to-license junction; license reports read `asset_components.license`). Both were empty. The demo component seed no longer writes the junction.
- **Upgrade note:** one step. A client that sent `include=stats` must drop it. Run the migration explicitly; `air` does not run migrations.
