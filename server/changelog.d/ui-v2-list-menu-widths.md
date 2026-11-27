### Changed: list menus are as wide as their content

- The saved views menu, the table's Display menu and the filter value menus (Status, Practice, State and the like)
  no longer pad to a fixed width: a short list opens as a short menu, a long one stops at the menu ceiling.
- Those menus, the "+N more" filters popover and the Findings Group and Export menus open under their trigger by
  the shared placement rule (start-aligned when it fits, end-aligned otherwise) instead of a side fixed per menu.
- The saved views menu's "Unsaved changes" sentence wraps at a reading measure and never widens the menu.

Docs: none (the rule is already in web/docs/ui-style-contract.md, "Floating surfaces"; this removes the last exceptions)
