### Fixed: a sensor's retest-templates capability and dnsx-enum tool are no longer dropped
- A sensor's `retest-templates:<tool>` capability (its retest handler also runs templates delivered with the command) was removed from every report as an unknown capability, so a retest with a custom check found no sensor and never ran. It is now kept for a tool in the catalog, like `retest:<tool>`.
- The `dnsx-enum` tool (subdomain brute force, `enumerate.subdomains@1`) is in the tool catalog (migration), so a sensor's report and manifest keep it.
- The sensor manifest tab says "This sensor is newer than the platform; these items will be used after the platform is updated" when every ignored item is one the platform does not know yet, and says some items are invalid otherwise.
