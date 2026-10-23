### Changed: asset filters are chips with Add filter instead of a side panel

- Every active filter on the asset list is a chip ("Criticality is Critical, High") with a remove button, in one row under the toolbar, with the result count at its end. Filters that are not facets (crown jewels, risk score, coverage, tags, date windows) have chips too.
- Add filter (or the `f` key) lists the filters by group with a search box; a picked filter opens its editor and applies as you tick.
- The side filter panel is gone from wide screens; phones and narrow windows open the same filters in a sheet.
- The filter labels and values are translated (English and Vietnamese).
- A cold load of the asset list no longer asks for the tag list and the business units; they load when a filter shows them.
