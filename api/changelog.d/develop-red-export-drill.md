### Fixed: two tests left red by concurrent merges

- The findings export decides the new `bounty_report` field (left out: researcher free text leaves the platform only through the UI), and the CTEM dashboard parity test drops the page-only `group` parameter before calling the findings list, which now refuses unknown parameters. Tests only; no behaviour change.
