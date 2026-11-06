### Added: weekly active subdomain enumeration on scope-entry domains

- Asset coverage now runs `enumerate.subdomains` (tool `dnsx-enum`) every 7 days on each `domain` asset under a scope entry. It brute-forces DNS labels from the platform's small wordlist pack plus the labels learned from the organization's own names, and keeps only names that resolve. This finds subdomains that passive sources miss.
- It is an active capability: it needs a scope entry, passes the full dispatch gate and the claim-time re-check, and is not on the low-impact list. The learned labels are read for the job's own organization only and sealed into the signed job.
- While the platform has no `wordlists-s` pack, the capability is paused with the new readiness reason `content_missing`, and its alert asks an instance administrator to import the pack. Coverage resumes on its own after the import.
