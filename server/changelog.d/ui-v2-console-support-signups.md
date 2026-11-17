### Changed: the console Support access and Sign-ups pages follow the shared list pattern (redesign branch)

- Console > Support access: a title row "Granted to you" with the count once above the grant cards (shown with the
  support permission only, as the cards are); a grant's expiry and case reference are two items instead of one line
  joined by a middle dot.
- Console > Sign-ups: the event feed is the shared table: a title row with the kind view and the count once, the
  kind as the table's own select, column kinds and widths with rows on one line, Network stepping aside on a narrow
  table, the load error and both empty states in the table, and the shared pager instead of Previous / Next.
- Sign-ups: the list comes first on every width; the 30-day counts follow it as one strip (today's count with the 7-
  and 30-day totals per kind, each tile filtering the list by that kind, the same request as the Event select).
  Before, three tall count cards put the list below the first screen of a phone. The strip keeps its labels while
  the counts load, so nothing moves when they arrive.
- No API change: the same reads, 50 events a page, the same Open support session dialog and alert thresholds form.
- Docs: none (layout of existing console pages; what they read and who may act are unchanged)
