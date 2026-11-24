### Fixed: filter sheet, filter values and tab strip in the web console

- On a phone the filter sheet opens from the bottom and is only as tall as its filters (two filters no longer fill the screen); a long filter list scrolls inside it, below a strip of the page.
- Filter tokens show their whole value ("Status: Awaiting approval") wherever the toolbar has room: the other values still reserve the same width as before, only a long value shown takes more, and it ends in an ellipsis only when the row is too narrow; the full value stays in the tooltip and the accessible name.
- Page tab strips that appear a moment after the page (the asset page waits for its reads) mark the edge that hides more tabs once shown, so the fade always shows where a tab continues past the edge; before, the strip could keep the "nothing hidden" state it measured while hidden.
- Docs: none (layout of existing shared controls, no documented behaviour changes)
