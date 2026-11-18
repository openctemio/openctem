### Fixed: pages stop scrolling after their last content

- Program health kept scrolling for a screen or more of empty background below its last card (about 690 px on a phone, 1,100 px on a desktop with a 90-day trend). The open-findings trend's data table for screen readers was hidden in a way that does not shrink a table, so the page grew by one row per day of the window. Such a table is now clipped inside a hidden box (a shared component), and a unit check refuses a hidden table written any other way.
- Lists without a pager (for example Attack surface exposures and Assets needing attention) ended with 16 px of empty scroll below the table: the shared list stacked its parts with spacing under every part but the last, and the last part was one that takes no room (the list's screen-reader status line, or on a phone the hidden desktop table). The parts are now spaced by a gap, which skips such parts.
- An end-to-end check measures every console page at 390 px and 1440 px: the scroll ends within the page's bottom padding plus 8 px after its last visible content, and the document itself never scrolls.
- Docs: none (layout fix, no change to what any page shows or does)
