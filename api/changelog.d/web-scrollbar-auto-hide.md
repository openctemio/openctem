### Fixed: page content no longer shifts when a scrollbar appears

- The page scroller always reserves its scrollbar gutter, so content keeps its
  width when a page becomes long enough to scroll. The scrollbar thumb is
  shown only while scrolling; wheel, trackpad, keyboard and touch scrolling
  are unchanged, and forced-colors mode keeps the system scrollbar.
