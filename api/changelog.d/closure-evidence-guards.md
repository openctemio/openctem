### Fixed: a closure needs evidence that survives a second look

- A retest no longer counts an edge block as a fix when the sensor sends per-request lines: the platform also classifies the recorded exchange at the finding's endpoint, and a CDN or WAF challenge or block stays `edge_blocked`.
- A retest no longer resolves a finding that a scan sighted again after the check ran: the fix is recorded `inconclusive` and the finding stays open.
- The one hour between two origin refusals of an exposure check is measured between the checks' completion times, not to the moment the second is settled.
- A retest of a non-exposure check that is answered by a redirect to another page (a login) is `inconclusive` (`auth_changed`), not a fix.
- A full-coverage import closes findings only for an uploader who also holds `findings:verify` (otherwise it imports and closes nothing, receipt note `needs_verify`), leaves critical and known-exploited findings open, and closes only findings whose latest sighting was an upload, never one a platform sensor saw last.
- A report observed before a finding was resolved no longer reopens it; a report observed after the fix still does.
