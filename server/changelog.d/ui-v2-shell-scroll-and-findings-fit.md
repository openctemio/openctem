### Fixed: a list opened from the sidebar starts at its top; findings rows fit their frame

- Opening another view of a list from the sidebar (Findings: Needs triage,
  Active, My queue and the rest; Assets views) after scrolling the list no
  longer leaves the page title under the app header: the app shell's columns
  can no longer be scrolled (they clip), screen reader text on a page stays
  inside the page scroller, and a page scrolled by less than the header's
  height also starts at its top. The admin console shell follows the same rule.
- Findings list: with the default columns the row menu ("...") is whole inside
  the table at 1024, 1280 and 1440 px, sidebar open or collapsed, with long
  titles and locations: a long title is cut by its ellipsis instead of widening
  the table, and Location narrows toward its floor before the table scrolls
  sideways.
- The Due / SLA chip shows its whole text ("109 d overdue", "Trễ 109 ngày"); a
  count above 999 reads "999+". The column is 140 px wide and the width points
  at which Severity, Signals and Due / SLA drop moved by 28 px accordingly.
- Docs: none (layout fixes of the redesigned console; no setting or workflow changes)

### Fixed: accessibility defects below the first screen of a page

- The dashboard's CTEM stage figures are named by their visible words first
  (a voice-control user can say what they see); the CI/CD GitHub App guide link
  in running text is underlined; secondary text no longer fades below the
  muted colour (evidence upload hint, onboarding bundle persona, group member
  "Added by", empty repository figures, empty attack-coverage cells).
- Docs: none (accessibility fixes, no behaviour change)
