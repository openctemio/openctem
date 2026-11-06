### Fixed: a report released from the quarantine counts under its sensor, not a connector

- A held sensor report that the platform later released (or a person accepted) was filed on a receipt of source kind connector, so the dashboard's Sources card showed a sensor's results twice, once as "Sensor" and once as "Connector". It is now recorded under the sensor that sent it, with the original tool, and marked "Released from quarantine" on the receipt list and the Sources card. How the report is applied does not change.
- Migration 20261106022653 adds the release marker columns (no backfill).
- A source made stale by one of its senders now says when that sender last reported, not when the freshest sender did.
- New operator command `receipt-reattribute` (a dry run by default, `-apply` to change) moves the receipts an earlier auto-release filed under a connector back to the sensor, only where the quarantine record shows the release.
