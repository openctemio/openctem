### Added: the platform admin console opens on what needs an administrator

- Console > Overview lists what to act on now, most severe first: organizations without an owner, emergency-access sign-ins, refused administrator actions, overdue break-glass tests, database schema drift, offline platform sensors, stuck scan runs and failed notifications, each with a link to fix it. New endpoint `GET /api/v1/admin/overview` (any console role; counts only).
- Ctrl/Cmd+K searches console pages and organizations.
- The console navigation is grouped Customers, Scanning, Security and System. System logs is now Security > Admin activity (`/admin/security/activity`, with a result filter) and Administrators is under Security (`/admin/security/administrators`); the old URLs are gone.
