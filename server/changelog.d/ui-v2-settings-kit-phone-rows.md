### Fixed: Settings headings, switch rows, the time zone field and phone cards fit a phone (redesign branch)

- A settings section keeps its chevron, switch or short button on the title line of a 390 px phone (a collapsed
  group of the Settings overview was about 137 px tall with the chevron alone on a second line); only actions that
  do not fit, such as two long buttons, wrap under the title.
- A settings row keeps its switch or short button at the end of the label's first line on a phone instead of
  under a long hint; a control that does not fit beside the text (a long button), text fields and selects still go
  under it.
- The time zone field (organization settings, scan schedules, approval rules) has the select field's look: one
  border, height, 16 px phone text and chevron with the other fields of the form; select fields now have 16 px text
  on a phone like text fields.
- On a list's automatic phone card a word longer than the card, such as a long e-mail address, breaks inside the
  card and no longer runs under the row's menu button.
- Docs: `web/docs/ui-style-contract.md` "Settings pages" (rows on a phone, picker trigger).
