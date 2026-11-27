### Changed: list headers that hold still (redesign branch)

- Practice, State, Group and Views keep one width per language whatever their value: a value, or a saved view's
  own name, is cut to that width with the full text in the tooltip and the accessible name. The Views trigger keeps
  the room of its unsaved-changes dot. The search field beside them therefore keeps one width per toolbar width.
- The chips row is exactly one line of one height: chips that do not fit fold into "+N more", the locked chip
  takes at most half the row (it no longer stacks above the chips), and Reset to view or Clear filters is pinned
  at the row's end after the count.
- Findings: Export and Task from filters stay in the title row (and in More) while the list is grouped.
- A stability check (e2e) holds Findings, Assets and Scans to 0 px of movement of every toolbar and title-row
  control through filters, grouping, views, the mode switch and typing, at 1440, 1024, 768 and 390 px, en and vi.
- A list says its count once, beside the view name in its title row (`ListCount`: the results with the filters and
  search applied, "1,000+" when counted only that far, announced once by screen readers). The chips row no longer
  repeats it ("0 assets" under the Assets toolbar is gone). Assets, Scans, Vulnerabilities, Emerging threats and
  the attack-surface Certificates, Technologies and Exposures lists show it in a title row of their own.
- Assets follows the list layout: the title row holds the view name, its count, Refresh and Export; the page header
  keeps Add asset and the list or category switch. An empty list shows its message in the table's own frame (a page
  empty state drawn as a card no longer adds a second frame inside the table, on every list).
- Query mode keeps Add filter, Practice and State in their place, dimmed and inactive (the query text owns the
  filter; `f` does not open the picker), and the toolbar keeps one alignment in both modes: on a
  toolbar that takes two lines (1024 and 768 px with the sidebar) switching modes no longer moves Views, Group and
  Display. The search field of a list with Query mode asks for 11rem before it grows, so the switch, the field and
  the tokens keep one line at 1024 px.
- Findings: the Location column grows from 160 up to 280 px into spare frame width before the title (floor 280)
  takes the rest; it no longer truncates a location beside an empty title column. The rule lives in the table's
  column fitting (`maxWidth` above `width` lets a column grow), so any list can use it.
- Sidebar quick views: on a hovered or focused row the pin takes the count's place; the count is never drawn under
  the pin (1 to 4 digits).
- Docs: web/docs/findings-list.md, web/docs/ui/shared-kit.md.
