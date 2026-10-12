### Changed: the session bootstrap carries the platform announcements

- `GET /api/v1/me/bootstrap` returns the active platform announcements in `announcements` (the same list `GET /api/v1/announcements` returns in `data`; an empty list when none is active). The web app shows the announcement banner from the bootstrap and no longer requests `/announcements` on every page load. `GET /api/v1/announcements` stays for other clients.
