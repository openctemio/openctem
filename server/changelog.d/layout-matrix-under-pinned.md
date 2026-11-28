### Added: layout matrix flags notices that stay while the page scrolls

- New detector kind `underPinned` in `web/e2e/helpers/layout-matrix.ts`: a notice (`role=alert|status`, `[data-slot=alert]`, a shell banner) that does not move while the page scroller does, and text covered by a sticky or fixed layer that can never be scrolled out from under it (at the top, at the end, or under a notice at any scroll). Self-tests in `web/e2e/specs/75-layout-matrix-under-pinned.spec.ts`.
- Docs: web/docs/ui-style-contract.md
