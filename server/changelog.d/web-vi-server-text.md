### Fixed: text written by the server reads in Vietnamese

- Asset activity: the Detail column worded the server's reason in English ("Asset created", "Discovered by scan"); each known reason now comes from the catalog.
- Scan runs: the Trigger column of a scan's runs said "Manual" and "On Asset Discovery" on a Vietnamese page; the trigger type is now worded from the catalog, on the runs table and the phone card.
- A finding's activity ("nuclei recorded this finding", "changed status Confirmed → In progress") and the reason of its priority class ("Medium severity, reachable", "capped at P2 until ownership is confirmed") are worded in the console's language; a reason a tenant rule wrote is shown as written.
- Error messages that pop up after a failed request had English titles ("Not Found", "Server Error") on every page; they now follow the console's language.
- "Couldn't load ..." messages named what failed in English ("activity", "domain proof", "affected assets"); a test now refuses a literal title.

Docs: none (wording only, no behaviour change)
