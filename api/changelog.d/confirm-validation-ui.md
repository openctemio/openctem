### Fixed: deleting an evidence file no longer reports success when the server refused it

- The evidence attachment delete showed "deleted" and removed the file from the list even when the request failed. It now checks the answer and reports the failure.

### Changed: pentest, validation, threat intelligence and dashboards ask before acting

- Deleting an evidence file, a campaign credential, a pentest finding, a report, a checklist or a compensating control asks you to type its name (or a short id). Deleting several reports always asks for the count and lists them.
- Closing a campaign asks for its name, and every campaign status dialog names the campaign. Activating or closing a CTEM cycle asks for the cycle name.
- Running an attack simulation says that it sends live safe-check traffic, and waits for a confirmation. Marking a report delivered, turning on a threat feed sync and making a dashboard the organization default are confirmed. Bulk retest requests show the count on the button and the findings.
- Downloading a flagged file and discarding a started campaign use the shared dialog instead of the browser's own. Deleting a compensating control moved into the row menu, away from Test.
- Deactivating an indicator is labelled as such. Hard-coded English in the report actions, the pentest finding sheet and the indicator dialog is translated, and em dashes were removed from the touched copy.
