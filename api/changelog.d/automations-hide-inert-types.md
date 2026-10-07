### Behaviour change: automations no longer offer triggers and actions that never run

- The `finding_updated` and `webhook` triggers never fired (nothing called
  them). They are no longer offered, and creating, editing or switching on an
  automation that uses them returns 400 `UNSUPPORTED_WORKFLOW_FEATURE`.
- The `trigger_pipeline` action ran a scan workflow outside any scan, with no
  targets, scope gate or scan history. It is refused the same way; an
  automation runs a saved scan with `trigger_scan`. The executor also refuses
  to run any refused action type still stored in an automation.
- Migration 001208 switches off every active automation that still uses a
  refused trigger or action. The automation stays readable and lists the
  refused types in `unsupported_features`; replace the node to switch it on.
- **Upgrade note:** none; the migration runs with the others.
