### Fixed: reasons, values and descriptions on several pages are no longer cut by an ellipsis

- Sensors: a sensor's reason ("takes no new jobs") and its heartbeat line wrap under its state in full.
- Needs attention: the line that says why a queue matters wraps beside the count from 1280 px; on narrower screens it is read in full at the top of the reason menu, as on a phone.
- Pentest finding and template editors: the CWE, OWASP and ATT&CK pickers show the chosen entry in full (the field grows like a select), and the summary card shows the title, campaign and targets in full.
- Organization settings: the URL host before the slug keeps its width, and the dashboard data state reads in full.
- Sensors filter panel: a long build version wraps.
- Open-source licenses: a module path and its version wrap instead of being cut.
- Compliance, checklists, import mappings, notifications and asset groups show their descriptions in full.
- Ticket mapping rows: below 1280 px the source takes its own line, so its selects keep the width of their values.
- A card's title (findings, exposures, vulnerabilities, exceptions, credentials, campaigns, tasks, receipts, sensors, assets) that ends in an ellipsis shows its full text as a tooltip.
- Docs: web/docs/ui-style-contract.md (layout rule, unchanged)
