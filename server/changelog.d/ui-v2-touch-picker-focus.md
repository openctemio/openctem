### Fixed: pickers no longer open the phone keyboard by themselves (redesign branch)

- On a touch screen, a picker, popover, sheet or dialog no longer focuses its text field when it opens, so the
  on-screen keyboard does not cover the options. Focus goes to the option list (its first option active) or the
  dialog body; the keyboard opens when the field is tapped. With a mouse or trackpad the field still gets focus.
  Command palettes, step-up confirmation, typed confirmation and one-field forms keep focusing their field.
- Add filter (and every picker with a search field) on a phone: the search field stays pinned at the top of the
  sheet, group headings stick while the list scrolls, rows are 44 px, and once the keyboard is up the sheet sits on
  it and never grows taller than the visible screen, so the field and the rows under it stay in view. Enter picks
  the highlighted option, the clear button keeps the keyboard up, and closing the sheet closes the keyboard.
- Docs: web/docs/ui-style-contract.md ("Focus on open")
