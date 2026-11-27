### Fixed: list rows, filter tokens, selects and the sidebar keep one clean shape

- Validation overview, "Waiting for you": each row reads as one list item, count, text and the row's action at its end (under the text on a phone). Every row action is an outline button: no queue row is the page's main action.
- A focus ring shows only for keyboard use. After a click or a tap no control draws the keyboard ring, even when the focus is moved by script (the sidebar opened over the page at 768 to 1023 px no longer outlines the current page's row at rest; a select or menu that gives the focus back to its trigger draws no ring). Text fields keep their ring, and the first key press brings every ring back.
- The sidebar's page list fades at its top and bottom edge while more rows are hidden that way, so a row cut under the organization switcher reads as "more above"; the sidebar opened over the page centres the current page's row.
- Filter tokens ("Target: All", "Status: All") hug what they show: no empty room before or after the chevron. The fixed scopes of the findings list keep one width, as before.
- Selects are one line, as high as the controls beside them: a long value ends in an ellipsis with its full text on hover (the notification history's channel picker no longer grows three lines tall; its provider shows in the list).
- The repository Findings filters use the standard control size beside the search.
- Docs: web/docs/ui-style-contract.md
