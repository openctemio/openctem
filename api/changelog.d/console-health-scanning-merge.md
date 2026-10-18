### Changed: the console has one Health page and one Platform scanning page

- Monitoring > Health now holds what Health (`/operations`) and System (`/system`) showed: services, storage, backup, certificates, schema and version, work queues, sensors and background jobs. The duplicated version, database and service blocks are gone.
- Scanning > Platform scanning (`/scanning/platform`) now holds what Platform scanning (`/system/platform-scanning`) and Shared sensors (`/system/shared-sensors`) showed, as the tabs Policy, Fleet, Queue, Zones, Egress and Anomalies. While shared sensors are not available in the release, the page shows one notice and the domain-proof policy instead of empty fleet tables.
- The language of the console can be chosen from the sidebar footer, and the last hard-coded English texts of the console moved to the translation files (English and Vietnamese).
- **Upgrade note:** the pages `/operations`, `/system`, `/system/platform-scanning` and `/system/shared-sensors` no longer exist and there are no redirects; update bookmarks to `/health` and `/scanning/platform`. The configuration overview and the "Needs attention" list link to the new pages.
