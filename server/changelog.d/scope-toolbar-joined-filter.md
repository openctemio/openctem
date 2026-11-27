### Fixed: the Scope lists' Filters button is joined to the search field

- On Scope (entries and exclusions) the Filters button kept four round corners and a doubled border beside the
  search field, because the popover around it replaced the button's slot name. The button now keeps its own
  slot, so the search joins it like on every other list (one outer border, round outer corners, one height).
- The Scope Filters popover is the shared `FilterPopover`; the toolbar guard no longer lists a Scope exception.

- Docs: none (a layout fix; the joined control is already described in web/docs/ui-style-contract.md)
