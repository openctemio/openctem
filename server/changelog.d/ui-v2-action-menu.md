### Added: one actions menu that becomes a bottom sheet on phones (redesign branch)

- `ActionMenu` renders the same items as an anchored menu from 768 px up and as a bottom sheet below: the
  object's name as the title with a close button, 48 px rows without icons, the destructive group last, the reason
  of an unavailable action as visible text, submenus opened in place with a Back row. It closes on the close button,
  Escape, a tap outside, a swipe down or a chosen action, and gives the focus back to its button. The sheet's code
  loads only when a phone first opens one.
- The Findings page-header More uses it; its "Create" heading over a single item is gone.
- The layout checks of the visual gate now also report an open popup nearer a screen edge than the gutter and an
  action-sheet row shorter than 44 px.
- Docs: web/docs/ui-style-contract.md ("Action menus: ActionMenu")
