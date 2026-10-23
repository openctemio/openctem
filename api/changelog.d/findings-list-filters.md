### Added: Add filter and filter chips on the findings list

- Every active filter on the Findings list is a chip, including the ones set in the filter panel. A chip's x removes only that filter.
- Add filter (or press `f`) opens a searchable list of every filter field the API offers, grouped as Exploitation, Finding, Asset and Work, and an editor for the field: choices, an operator with a number, quick date ranges, yes or no, empty, or a member picker. Fields the API adds later appear without a console update.
- Filters from the open saved view show first with a lock and cannot be removed from the list.
- A filter in a shared link that no field knows is shown by name with a remove button instead of being ignored; a link the API refuses explains which filter and offers to remove it.
- Asset-derived filters (asset tag, criticality, group, owner) are only offered to people who can read assets.
