### Added: inline monitoring decisions and scoping decision cards on Assets

- The monitoring state of an inventory row is a menu for a caller with `assets:write`: Ours, Watch only, Ours on third-party infrastructure, Not ours, or Undo the decision, each with what it does; a pick records the ownership decision through `PUT /api/v1/assets/{id}/attribution` (audited, unchanged).
- Assets > Needs attention gains a "Scoping decisions" group with two queues, Validate primary assets (root domains not yet confirmed) and Decide monitoring (names awaiting review or with too little evidence); the same cards show above the inventory while assets wait.
- `GET /api/v1/assets?primary=true` keeps primary assets only: domain assets named like the root of a permanent domain scope entry or a verified domain, tenant-scoped.
