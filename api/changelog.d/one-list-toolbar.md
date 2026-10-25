### Changed: every list has the same toolbar

- The search box is now the first control of every list toolbar, at the same place and size on every page: 36px high, the search icon at its start, a placeholder that names what it matches ("Search name, host, IP, version or tool…"), a clear button while there is text, and Escape to clear it.
- On lists with a filter panel, the filter button is joined to the start of the search box on every page (it sat 8px away on some lists and flush on others), keeps the same filter icon when the panel is open, and looks pressed instead.
- Status and kind selects follow the search; group, export, refresh and the table menu stay at the far end, the table menu last. That menu (row density and columns) is now called "Display", so it is no longer confused with saved "Views".
- Active filter chips sit in one line under the toolbar that never wraps: chips that do not fit fold into "+N more", which lists them (each still removable). Add filter and Clear filters follow the visible chips, and the result count stays pinned at the end. What a list always hides (on Assets: names awaiting review and not ours) is a quiet locked chip first in that row, with a "Show" button.
- New list shortcuts, listed under Help > Keyboard shortcuts: `/` focuses the list's search box, and `F` opens the filters on lists without "Add filter" (where "Add filter" exists, `F` still opens it).
- Search fields in drawer lists (team assets, members and scope rules, role permissions and members, campaign checklists) use the same search box.
