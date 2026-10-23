### Fixed: the Exposures overview matches its lists and reports bulk results honestly

- The "Resolved" tile is now "Closed" and counts resolved, accepted and false positive exposures, the same states as the view it opens.
- Bulk accept and bulk false positive no longer show a success toast for exposures that went to a second approver. The result is reported once: applied, waiting for approval, and "x of N failed".
- Bulk actions run at most 5 requests at a time, keep going after a failure and always refresh the list, so rows that changed are not left stale.
- A failed statistics request shows an error with a retry button in the metrics strip and the Analytics tab instead of zeros.
- Copy changes: the export and page description no longer use dashes as asides.
