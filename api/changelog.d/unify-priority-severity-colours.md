### Changed: priority classes, severity, KEV and SLA pills use one set of colours everywhere
- Priority classes P0 to P3 are a filled class box on the brand ink ramp (P0 strongest), no longer the severity hues, so P1 can no longer be read as "High". Severity stays a soft pill with a dot. Teal is used for neither.
- One `PriorityBadge`, one `SeverityBadge` and one `KevBadge` replace the ad-hoc renderings; charts, legends, finding status pills, SLA state pills, risk bands and criticality read the same tokens in light and dark (all at AA contrast).
- The palette-drift gate now refuses a hand-written priority or severity colour outside the shared modules.
