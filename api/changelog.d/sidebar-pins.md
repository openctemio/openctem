### Added: pinned pages and findings views in the sidebar

- Members pin pages, findings quick views and saved views to a Pinned section at the top of the sidebar, in their own order (up to 12 per organization). Each pinned view shows its live count, computed as the member, so it equals the list it opens.
- New `GET /api/v1/me/pins` and `PUT /api/v1/me/pins` (self-scoped). A saved view pin is shown only while the member can still see the view; page pins must be in-app paths. The session bootstrap (`GET /api/v1/me/bootstrap`) carries the pins with their counts as `pins`, so the sidebar adds no request to a page load. Migration `nav_pins`.
