### Fixed: web console menus are as wide as their content and open under their trigger (redesign branch)

- A menu is as wide as its content: at least its trigger or 128 px (160 px with icons), at most 360 px or the
  screen less both gutters. Fixed widths that only padded short lists are gone (the finding status menu opened
  256 px wide for two short items); a guard test lists the menus whose content needs a width, with the reason.
- A menu, popover or select list lines up with its trigger's start edge, and with the end edge only when the start
  would cross the screen gutter or the edge of the drawer or dialog it was opened from. A menu opened in the
  finding drawer now opens under its trigger inside the drawer instead of hanging out over the page.
- Docs: web/docs/ui-style-contract.md ("Floating surfaces")
