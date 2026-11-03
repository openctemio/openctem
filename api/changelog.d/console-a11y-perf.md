### Fixed: console filters and tables are keyboard and screen-reader correct, one version check read per page
- The platform console's list filters (Users state, Configuration, AI applications) are radio groups (the shared lens control) instead of tabs without panels, which pointed `aria-controls` at nothing.
- Every table scroller is a focusable, named region, so a table wider than a phone screen scrolls with the keyboard.
- The console reads the version check once per page (one SWR key, no trailing slash) instead of twice.
