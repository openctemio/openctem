### Fixed: threat intelligence feeds report what they did

- An unchanged CISA KEV catalog (HTTP 304) no longer overwrites the stored record count with 0; a count an earlier run already zeroed is repaired from the catalog.
- A KEV response with no entries (an empty or renamed `vulnerabilities` array) and an empty EPSS file are failed syncs. The validators of a bad KEV response are not stored, so the next run fetches again.
- KEV and EPSS refuse a snapshot smaller than 90% of the stored catalog.
- `POST /api/v1/admin/threat-intel/sync` always answers 200 with one result per feed (`success`, `error`); it no longer answers 206 on a failure, which the console showed as "Sync finished." It accepts `vulnfeed` and "all" includes it. A feed that is switched off or not configured is reported as failed.
- The organization routes (`GET /api/v1/threat-intel/sync`, `/sync/{source}`, `/stats`) no longer return the raw `last_error` text of a failed fetch; the platform admin route still does.
