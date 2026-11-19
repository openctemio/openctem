### Fixed: first visit to the dashboard in two tabs at once

- A person with no dashboard who opened the dashboard in two tabs at the same
  time could see "You have no dashboards yet" in one of them: both tabs asked
  for the personal copy of the default template, and the server refuses the
  second copy because names are unique per person. The tab whose copy was
  refused now reads the list once more and opens the copy the other tab made;
  the empty state shows only when the list is still empty.
- Docs: none (a fix of documented behaviour; no setting, screen or text changes).
