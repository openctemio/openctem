### Added: a tool a sensor declares joins the organization's tool catalog

- A tool a sensor reports in its manifest with a valid tool contract (RFC-055) is no longer dropped as `unknown-tool` when the catalog has no row for it: the organization's catalog gets a row projected from the tool's descriptor (display name, description, capabilities, target types, settings schema, version), and the tool can be enabled, configured per sensor and scanned with like any catalog tool. A newer version refreshes the row. RFC-092.
- A declared tool never takes a platform tool's name, never overwrites a member's own tool, is limited to 128 per organization and is edited only through its sensor (the API refuses editing or deleting it; deactivating it still works). Platform sensors declare nothing. Its tier, trust, grant and scope rules are unchanged: an operator-installed tool still runs only as T2.

### Fixed: the tool catalog lists a tool without an install method

- A tool row whose `install_method` is empty no longer makes the tools list fail with an internal error.
