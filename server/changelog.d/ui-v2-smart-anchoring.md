### Changed: web console popups place themselves by where their trigger is (redesign branch)

- Menus, popovers and select lists line up with the start or end edge of their trigger by the half of the screen
  the trigger is in, so a menu whose button moves to the left of a wrapped phone row opens rightwards from it
  instead of being pushed against the gutter.
- They keep at least the safe area from the screen edges, keep 16 px above a fixed bottom row that registers
  itself, are never taller than the room on their side (they scroll inside, with a shade at the edge where there
  is more), never wider than the screen less both gutters and never narrower than their trigger.
- Select lists open under their trigger instead of over it; a menu heading over a single item is hidden; shortcut
  hints are hidden on touch screens; tooltips open after 400 ms; popups do not animate under reduced motion.
- Docs: web/docs/ui-style-contract.md ("Floating surfaces")
