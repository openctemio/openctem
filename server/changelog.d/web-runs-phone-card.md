### Fixed: phone cards stay compact whatever a run's message holds (redesign branch)

- Scan runs on a phone: a run with a message (every partial or failed run has one) showed "Status" with no value and
  then an empty box taller than the screen. The message wrapped in the few pixels the state left beside it, and the
  state sat at the middle of that height. Each run is now a card with fixed lines: the scan, the state with its
  reason on one line (cut, whole in the hover text and in the run's sheet), the tasks and findings, then who started
  it, when and for how long. No label/value grid.
- Every list that draws its cards from the table columns: a cut text in a card wraps to three lines at most, and a
  cell's row wraps, so a long text goes under the chip beside it with the whole width.
- No API change.
- Docs: none (layout of existing phone lists; nothing to set or learn)
