### Fixed: the console's "Changes" view of administrator activity no longer lists sign-ins

- `GET /admin/audit-logs?kind=changes` now also leaves out sign-in, second-factor, step-up, elevation and session events (it already left out page views and write-ahead rows). "All events" still lists every row and no row is dropped from the chain. The console overview links for emergency sign-ins and refused actions open "All events".
- Console: audit action names, sign-in methods, roles and statuses read as translated labels (English and Vietnamese); one set of role names (platform owner, platform admin, read-only) everywhere; the audit detail sheet shows the exact UTC time and the reason, and no empty rows.
- Docs: none (the filter label already reads "Changes"; no user guide describes sign-in rows in that view)
