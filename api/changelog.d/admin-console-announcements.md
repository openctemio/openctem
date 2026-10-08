### Added: platform announcements and a threat-intelligence feeds page

- System > Announcements in the admin console publishes a one-line notice (maintenance, warning or information, at most 31 days) that every signed-in user sees as a dismissible banner while it is active. Operations admins and up publish or end one with a reason; both are audited. New table `platform_announcements` (migration 001370); signed-in users read the active ones at `GET /api/v1/announcements`.
- System > Threat intelligence shows the EPSS and CISA KEV feed sync state and lets operations admins run a sync now or turn the scheduled sync off.
- **Upgrade note:** apply migration 001370.
