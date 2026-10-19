### Security: a fixed VEX statement needs findings:verify

- A VEX statement with status `fixed` resolves every covered finding tenant-wide with verification `vex_statement`, which is a verification act, but only `findings:approve` was required. Writing a `fixed` statement now also needs `findings:verify`: `POST /api/v1/vex-statements` with status `fixed`, `PATCH /{id}` that makes a statement `fixed` or changes the versions, range or expiry of a fixed one, and `POST /import` with any `fixed` statement in the document (refused as a whole with 403, nothing written). The service enforces it, so other callers cannot bypass the route check.
- `not_affected`, `affected`, `under_investigation` and delete are unchanged (`findings:approve`).
- **Upgrade note:** the "CTEM program lead" role template has `findings:approve` but not `findings:verify`, so members of that template can no longer publish `fixed` statements until `findings:verify` is granted. Role templates are not changed.
