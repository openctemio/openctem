### Added: Settings → Scanning → Tool defaults, and sensor Tool settings as overrides

- A new page, Settings → Scanning → Tool defaults, lists every tool that the organization's sensors report with settings. Owners and administrators edit each tool's organization defaults there, and the page lists any sensor whose tool version refuses them. Members with `sensors:read` see the page read-only.
- In a sensor's drawer, Tool settings now shows overrides only. Each option shows the value in use and where it comes from: the tool default, the organization, or this sensor. **Override** and **Reset to organization default** change that per option. A tool's summary reads "2 overridden". The effective table names the layers that each value overrides.
- The options come from each tool's own settings schema; no tool is hard-coded in the page.
