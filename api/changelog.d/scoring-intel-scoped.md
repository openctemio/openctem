### Changed: EPSS and KEV refreshes recompute only the findings whose CVE changed

- After the daily threat-intel refresh, only open findings whose catalog EPSS crossed a threshold the classifier or one of the organization's priority rules uses, or whose CVE entered or left KEV, are queued for a new priority and SLA deadline. Before, a KEV refresh queued every finding of each touched organization and EPSS changes reached no finding at all.
- Daily EPSS drift that crosses no threshold no longer causes work; closed findings are never recomputed.
