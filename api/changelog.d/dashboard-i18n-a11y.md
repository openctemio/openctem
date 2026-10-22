### Fixed: dashboard widget gallery groups are announced correctly

- The widget gallery's group filter is a set of toggle buttons instead of tabs without panels, so
  screen readers announce it correctly.
- Dashboard surfaces are checked for complete English and Vietnamese text and for accessibility on
  every change (no user-visible change beyond the fix above).
- Dashboard widgets are visible on a phone: the column span of a wide widget is applied only once
  the grid has that many columns, instead of collapsing the widget to zero width on a one-column
  grid.
