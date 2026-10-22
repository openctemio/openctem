### Added: dashboard home renders stored dashboards

- `/` now shows your stored dashboards with one renderer: every widget is drawn from the dashboard's
  stored snapshot, with its own error state, so one bad widget never blanks the page.
- One switcher lists Organization dashboards (only with organization dashboard access) and your own,
  with search when there are many.
- A badge says whether the figures are organization-wide or for your own scope; a freshness line shows
  when they were computed and the next refresh, with Refresh now and, for owners and organization
  dashboard managers, the refresh schedule.
- Duplicate an organization dashboard to your own, set defaults and delete from the dashboard menu.
- A person with no stored dashboard still sees the built-in overview.
