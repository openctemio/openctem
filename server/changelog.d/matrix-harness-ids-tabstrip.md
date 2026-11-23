### Fixed: layout matrix checks id pages and swipe tab strips correctly

- The matrix "opened" check compares the browser path with the address it resolved (`/assets/<id>`), not the route template, so id pages no longer fail every variant; a redirect such as a bounce to the sign-in page still fails.
- The cut-text check skips a label past the edge of a page tab strip only when that strip really scrolls sideways and fades the cut edge; a clipped strip, or an edge with no fade, is still reported.
- The matrix waits for web fonts, finite animations and two frames before measuring, so a defect is no longer reported in one variant and missed in an identical one.
- Docs: none (test harness only; no product behaviour changes)
