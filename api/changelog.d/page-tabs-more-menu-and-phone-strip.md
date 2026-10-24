### Changed: page tabs never cut a label, metric strips fit two rows on a phone

- Route tabs that do not fit drop their icons first, then move the last tabs into a More menu at the end of the strip. The current tab always stays in view and no label is cut at the edge ("Approv…"); the strip no longer scrolls sideways.
- Tab icons follow one rule: every tab of a strip has its own icon or none does, drawn at 16px in the tab's text colour. Exposures, Attack surface and Business context tabs got distinct icons where two tabs shared one.
- A metric strip on a phone uses compact tiles in at most two rows (five tiles: three over two) instead of three rows of two.
- An empty list no longer shows "Showing 0 - 0 of 0" and "Page 1 of 0" under its empty state.
- New shared filter token for a list's state ("Status: Pending", counts per value in its menu, value in the URL), replacing segmented controls used as row filters.
