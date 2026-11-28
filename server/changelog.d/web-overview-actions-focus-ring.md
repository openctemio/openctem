### Fixed: list rows, filter tokens, selects and the sidebar keep one clean shape

- Validation overview, "Waiting for you": each row reads as one list item, count, text and the row's action at its end (under the text on a phone). Every row action is an outline button: no queue row is the page's main action.
- A focus ring shows only for keyboard use. After a click or a tap no control draws the keyboard ring, even when the focus is moved by script (the sidebar opened over the page at 768 to 1023 px no longer outlines the current page's row at rest; a select or menu that gives the focus back to its trigger draws no ring). Text fields keep their ring, and the first key press brings every ring back.
- The sidebar's page list fades at its top and bottom edge while more rows are hidden that way, so a row cut under the organization switcher reads as "more above"; the sidebar opened over the page centres the current page's row.
- Filter tokens ("Target: All", "Status: All") hug what they show: no empty room before or after the chevron. The fixed scopes of the findings list keep one width, as before.
- Selects are one line, as high as the controls beside them: a long value ends in an ellipsis with its full text on hover (the notification history's channel picker no longer grows three lines tall; its provider shows in the list).
- The repository Findings filters use the standard control size beside the search.
- Table rows keep 4 px above and below their content (compact rows excepted), so a cell of two lines no longer touches the row's lines.
- One text size per row: the top bar's search uses the size of the buttons beside it; a toolbar select shown as an icon is a square again at tablet width (the sensors list's grouping select stood 144 px tall); the ticketing field mapper drops its small text and ends each row's frame at its last button on a wide screen.
- Notices stop at 56rem on a wide screen, so their sentences are not one 1500 px line.
- Long values that end in an ellipsis show their full text on hover (the executive summary's top risks, the classification pickers' hint); narrow tables leave a column instead of running past their edge in Vietnamese (emerging threats, executive summary).
- Docs: web/docs/ui-style-contract.md
