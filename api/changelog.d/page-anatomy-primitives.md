### Added: page anatomy and type scale primitives for the web console

- `PageStack` owns the vertical rhythm of a page: 16px from the page header to its tabs, 20px between every other block. A block that renders nothing no longer leaves the next one flush against the tabs.
- `MetricStrip` tiles can link to their list (`href`); on a phone the strip is two columns with no sideways scroll; a zero is a muted 0; the strip keeps its place with a dash per value when the numbers fail to load.
- `ListToolbar` is the one toolbar row above a list (the table toolbar uses it): filters and search first, views, export and the View menu last.
- Type scale tokens (`text-title`, `text-section`, `text-body`, `text-meta`, `text-data`, `text-kpi`) and text layout primitives: `MetaLine` (one size per metadata line), `KeyValueList`, `ListItem` and `TokenText` (middle-truncated hashes and URLs with the full value in a tooltip). Relative times take the size of the line they sit in.
- A web CI gate refuses added `StatsCard` tiles, hand-built metric tiles, arbitrary text sizes, two text sizes on one line and margins on route tab strips.

### Fixed: asset drawer Technologies rows no longer break names letter by letter

- Each technology shows its name on its own line and one metadata line under it (confidence, source, first seen, last seen) in one size.
- The lifecycle snooze menu is translated (English and Vietnamese).
