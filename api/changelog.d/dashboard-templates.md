### Removed: built-in CTEM and Classic dashboard views

- `/` shows only stored dashboards. The built-in CTEM and Classic views, the analyst charts and the
  legacy widget tiles are removed, with their untranslated text.
- A person with no dashboard at all gets a personal copy of the new Overview template on their first
  visit, computed for their own access.
- Templates (Overview, Executive, Vulnerability program, Triage) are typed widget configs; the
  dashboards page copies them, and every template widget is checked against the server's validation.
- The dashboards page is translated (English and Vietnamese). Changing a dashboard's column count
  now keeps each widget's share of the row instead of resetting every widget to one column.
