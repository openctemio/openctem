### Changed: a browser check fails on broken layouts in lists

- A new browser check (`web/e2e/specs/75a-layout-breaks-lists.spec.ts`, with 75b settings, 75c shell and 75d detail pages) opens the lists and their row menu, filters, detail sheet and main dialog at 390, 1024 and 1440 px, in English and Vietnamese, with long names and empty and present optional fields, and fails on text drawn over text or a control, a word broken inside, text cut without an ellipsis, controls of different heights in one row, English left on a Vietnamese page and labels without a value.
- A dashboard's description is marked as stored text, so the check does not count it as English left on a Vietnamese page.

Docs: web/docs/ui-style-contract.md (Responsiveness)
