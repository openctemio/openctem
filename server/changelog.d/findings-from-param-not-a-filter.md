### Fixed: no "Unknown filter" chip after drilling into a findings group

- Opening a group's findings (for example Findings, By rule) added the navigation parameter `from` to the URL, and the filter bar showed it as a red "Unknown filter" chip and counted it as an active filter. `from` is now a navigation parameter, not a filter: no chip, no count, and it is not saved into a saved view. The breadcrumb back to the grouped view is unchanged.
- Docs: none (bug fix, no behaviour to document)
