### Fixed: the selected tab is never left under the strip's edge fade (redesign branch)

- In a tab strip that scrolls sideways (a phone, a record with many tabs), a tab chosen near the end could stay
  half hidden under the fade that marks more tabs. A tab under that fade now counts as hidden and the strip
  scrolls it fully into view.

Docs: web/docs/ui-style-contract.md
