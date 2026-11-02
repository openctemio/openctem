### Changed: the platform console uses the same UI components as the main app, checked by lint

- Console pages and components may no longer hand-roll a list table, a raw HTML table, an alert dialog or tabs used as a filter: lint points to the shared component. Files that predate the rule are listed and move one PR at a time. The component map is in `web/docs/ui/shared-kit.md`.
