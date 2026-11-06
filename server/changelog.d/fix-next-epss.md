### Added: Fix next rows carry the finding's EPSS probability

- The `fix.next` and `sla.at_risk` list widgets return `epss` (0 to 1) on each row when the feed has a score for the finding, and omit it otherwise. The dashboard draws the shared EPSS bar from it. Snapshots stored before this change lack the field until they refresh; the bar then shows no score.
