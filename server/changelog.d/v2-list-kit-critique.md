### Fixed: list pages waste no rows and contradict no counts

- A list that fits one page has no pager ("Page 1 of 1"), and "Display" is never a button alone on a row.
- The list's name and count join the toolbar row; on a phone a row holding only the count is gone (the footer says it).
- Summary tiles over a list sit after the list on a phone on every list page, and are not drawn over an empty list or when they all count zero.
- The phone filter sheet has one heading (Clear all moves beside "Show results"), and its selects take the whole width.
- Phone cards no longer cut field labels, draw a switch as a dot, or squeeze a second name part into a narrow column.
- Card and section headers keep their button on the title's line.
- Docs: web/docs/ui-style-contract.md (Metric strip, Lists)
