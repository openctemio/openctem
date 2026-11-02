### Fixed: modules follow their hard dependencies, and presets stay within reach

- A module is off whenever a module it hard-requires is off: a deny of compensating controls, scanner templates or scope now also stops control testing, rule sources and CTEM cycles (routes, jobs, MCP tools, console), and a dependent of a module in its read-only grace is read-only until the same date.
- A preset changes only the modules Settings > Modules lists, so it can no longer switch off a module no page can switch back on; a module the organization is not entitled to is reported as unavailable instead of failing the whole preset.
- IOCs and suppressions, which own console pages, are listed on Settings > Modules.
