### Changed: audit log in the settings page frame

- Settings, Audit log: the filters move into Add filter (Result, Severity, Period of 24 hours, 7 days or 30 days, and Hide system events), shown as chips; on a phone they open in a sheet. The address keeps them (`?result=`, `?severity=`, `?period=`, `?hide_system=true`); old `?result=all` links are ignored.
- The toolbar shows the event count, with Export and Refresh. The summary strip above the list is gone; the period is fixed until Refresh, so the count and the pages agree.
- Rows use the shared severity badge, and phone cards show who did what and when. The export confirmation names how many events it holds, the period and whether system events are hidden. Resource and Request ID labels are translated.
- Docs: none (the page keeps its route, its actions and its permissions)
