### Fixed: Asset groups list widths and the phone start (redesign branch)

- A long group name has no width of its own: it ends in an ellipsis inside the Name column and never makes the
  table wider than its frame (in Vietnamese at 1280 px the table was 80 px wider than its frame; at 1024 px the
  columns now fit the frame).
- On a phone the metric strip is hidden by the layout (no movement after the first paint), and the page's English
  description is one line, so the first group card starts within the top 45 % of the screen with a filter on.
- Docs: none (internal redesign branch)
