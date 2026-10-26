# Sidebar pins

A member pins pages and findings views to the top of the sidebar ("Pinned"), in their own order, with a live count
beside each view. Pins are per member and per organization.

## Model

`nav_pins (tenant_id, user_id, kind, ref, position)`, unique on `(tenant_id, user_id, kind, ref)`, at most 12 per member.

| Kind | Ref | Shown as |
|---|---|---|
| `page` | an in-app path (`/my-work`) | the sidebar's own title and icon for that path; left out when the sidebar does not offer the page to this member (permission or module) |
| `quick_view` | a built-in findings quick view key (`needs_triage`) | the view's label, its list link and its count |
| `saved_view` | a saved view id | the view's name, `/findings?view=<id>` and its count |

## API

- `GET /api/v1/me/pins` returns the pins in order, with `name` (saved view), `params` (quick view), `count` and the
  member's `include_informational` (how a quick view's link is built).
- `PUT /api/v1/me/pins` replaces the list (the sidebar sends the whole list after a pin or unpin).
- `GET /api/v1/me/bootstrap` carries the same body as `pins` (`NavPinHandler.Response`, read for the bootstrap
  request's own caller), so the sidebar sends no request of its own on a page load. A failed read is left out and the
  web then asks `GET /me/pins` once.

Every count of one response comes from one statement: the views' filters are compiled together as facets over the
caller's visibility (`VulnerabilityService.CountSpecs`, the same compiler as the findings list), so a count always
equals the list the pin opens.

## Security

- A pin is a bookmark, never a grant. A saved view pin is shown only while the member can still see the view (a
  deleted or unshared view drops out of the response and stays stored), and opening it runs the view as the member.
- Writes validate every ref: page paths are lower-case in-app paths (no scheme, host, query, `//` or `..`); quick view
  keys must exist; saved views must be visible to the caller now. The web builds links through `safeHref`.
- Self-scoped route: tenant and user come from the session. Tests: `nav_pins_db_test.go` (own list, scoped counts equal
  list totals, another member's private view refused, deleted view drops out, bad refs refused and nothing stored,
  rows keyed by organization, the bootstrap's pins equal to `GET /me/pins` for the caller and empty for another
  member) and `bootstrap_session_test.go` (pins read for the bootstrap request's own caller, a failed read left out).

## Console

The Pinned section sits above the navigation. Pages pin from their sidebar row, quick views from their row under
Findings, and saved views from the saved views menu (the pin button on hover or focus). The list and its counts come
from the session bootstrap (seeded into the SWR cache under `/api/v1/me/pins`, not revalidated on mount, focus or
reconnect); a pin or unpin writes the saved list back into that cache.
