### Fixed: Sensor menus offer only the actions the API allows

- Enable is offered only for a disabled sensor, and a revoked sensor offers only View and Delete in the row menu, the detail drawer and the edit dialog.
- Revoke follows the API gate (`sensors:write` or `sensors:revoke`), not `sensors:delete`.
- The zones health action needs `sensors:zones:read`, the selection column needs `sensors:delete`, and the Disable confirm shows a loading state.
- The one-time API key dialogs (rotate key, install with a key) ignore outside clicks and ask "Did you copy the key?" before closing.
