### Fixed: the findings page no longer loads the source catalog on every visit

- The Add finding dialog, which stays mounted on the findings page, loaded the finding source catalog on every page load. It now loads it when the dialog opens, so the page stays within its request budget again (the develop E2E request-budget spec was red since the quick-views change).
- No operator action.
