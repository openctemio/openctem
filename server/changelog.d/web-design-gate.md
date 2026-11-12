### Added: design gate for redesigned pages

- New CI workflow "Web design gate" (`Design gate OK`): every page listed in `web/e2e/design/manifest.ts` is loaded with the design's sample data from a mock API and compared, at 1440 and 390 px in light and dark, with the reference images exported from its design board (`web/scripts/design-reference.mjs`, board hash recorded in the manifest). A layout pass in Vietnamese with long and empty data fails on sideways scroll, clipped text and overlapping controls. Seeded with the sign-in page: the layout pass blocks, the comparison reports as pending until the page moves to its board. Guide: `web/docs/ui/design-gate.md`.

### Fixed: a long single sign-on provider name no longer pushes the sign-in form past its card

- On `/login?org=...` an identity provider with a long display name widened the "Sign in with ..." button and the whole form beyond the card, cutting off the fields and buttons at every width. The name now ends in an ellipsis and the full text is in the button's tooltip.
