### Fixed: the organization time zone can be set, and settings controls that did nothing are gone

- Settings > General has a time zone picker. The organization time zone already set emerging-threat quiet hours, the digest hour and scan approval hours, but no page set it, so every organization ran on UTC. Any IANA zone is accepted now; the old allow-list of 15 zones is gone (the zone database is embedded in the API binary).
- Account > Preferences no longer shows a time zone, date format and time format: they were saved in the browser and no date formatter read them. Dates use the browser's zone and locale until one shared formatter honours a personal choice.
- Settings > AI is shown only to owners and administrators (the API was already admin-only; members and viewers saw the page with an error). The pentest report templates page now has its permission and module guard.
- Changing a member's role from the role sheet goes through the shared client, so a change that needs a recent sign-in asks for it instead of failing with "HTTP 403".
