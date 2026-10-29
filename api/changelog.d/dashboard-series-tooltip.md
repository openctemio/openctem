### Fixed: dashboard time-series charts show their values on hover, focus and tap

- Area charts showed only the date in an empty box (the row text took the series' card-coloured stroke). Every dashboard-kit time-series chart (columns, area, line, new vs fixed) now uses one tooltip: the span of the bucket ("Week of Oct 20 – 26"), one row per series in the order the marks are stacked with its palette colour, value and change against the previous bucket, a Total for stacks, a Net change for new vs fixed, and zero series folded into one line on charts with three or more series.
- It opens on hover, on keyboard focus of the chart (arrow keys move between buckets) and on tap.
