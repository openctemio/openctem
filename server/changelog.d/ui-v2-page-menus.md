### Changed: web console page menus use the shared action menu (redesign branch)

- The "⋯" menus of the list pages (scans, workflows, automations, exceptions, controls, dashboards, approvals,
  notification outbox, members, asset group) and the detail drawer's More are the shared action menu: an anchored
  menu, or a bottom sheet titled with the object on a phone without room. Destructive items come last, every
  unavailable item says why, and the trigger is named in English and Vietnamese.
- Members: the actions an administrator may not take on another administrator are dimmed with the reason; a
  pending ownership transfer explains why a second one cannot start.
- Below 768 px the page reserves no scrollbar gutter, so sheets and menus in a narrow desktop window reach the right
  edge of the window instead of stopping 10 px short.
- A test fails on a new hand-built "⋯" menu.
- Docs: web/docs/ui-style-contract.md ("Action menus")
