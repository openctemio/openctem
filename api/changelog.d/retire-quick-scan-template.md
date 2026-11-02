### Changed: the "Quick Scan Template" workflow no longer shows as Not available

- The leftover system workflow "Quick Scan Template" named a capability no tool provides, so it always showed as Not available in the workflow list. It is now retired (deactivated, not deleted): quick and single scans do not use it as a workflow and keep running as before, and their runs keep their link to it.
- Migration 20261031033816 deactivates it; its down migration reactivates it.
