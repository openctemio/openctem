### Changed: the dashboard's name is its switcher

- On the dashboard (`/`) the switcher is a chevron right after the
  dashboard's name instead of a field in the toolbar; it opens the same menu
  (Organization, Mine, search, New dashboard, Manage dashboards).
- The toolbar at the end of the title row is Customize (from 640px), an
  icon-only Refresh now and More, at every width. The refresh schedule moved
  from a toolbar picker into More as a submenu, also on a desktop.
- Below 640px the freshness line under the name never wraps, so the header
  keeps its height as the minutes tick: it leaves out the next refresh and
  "Refreshed on request only" (a screen reader still reads them), and a long
  scope label is shortened before the time is.
- A person with no dashboard sees the shared empty state with a New dashboard
  button. Widgets sit 16px apart at every width.
- Docs: server/docs/architecture/dashboards.md ("Switcher", "Toolbar");
  web/docs/ui-style-contract.md (action menus).
