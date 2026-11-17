### Fixed: console pages no longer shift when the web font arrives (redesign branch)

- The console preloads the Inter files its first paint uses (Latin; plus Latin Extended and Vietnamese on a
  Vietnamese page), so they arrive with the stylesheet.
- A size-adjusted fallback face (a local Arial or Liberation Sans with Inter's width, ascent and descent) follows
  Inter in the font stack of both apps, so a page that paints before the font arrives does not re-wrap or move
  when it swaps in. `font-display: swap` is unchanged.
- Docs: `web/docs/ui-style-contract.md` (fonts)
