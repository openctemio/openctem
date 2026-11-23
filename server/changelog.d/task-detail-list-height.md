### Fixed: the finding list of a remediation task ends at a whole row

- Remediation task page: the boxed finding list ends at the bottom of the last row that fits, so a row is never cut in half at the box edge before you scroll; the list still scrolls inside its box and loads later rows as you scroll.
- Layout matrix (tests): the full-page picture grows only by the page's own scroller, not by a scroll box inside it (a long task list made a 10,000 px picture of empty page), and a new `emptyTail` detector fails a picture more than 1.5 times as tall as its last visible content.
- Docs: none (layout fix of an existing page and test tooling, no behaviour change)
