# Brand assets

The OpenCTEM logo: the Scope "Caught" symbol (two corner brackets, the marker caught in the open corner) and an outlined Sora 600 wordmark.

These SVGs are the single source of truth. Never copy geometry by hand: edit the masters here and run `node web/scripts/brand-gen.mjs`, which writes `src/assets/logo.tsx`, `src/assets/brand-data.generated.ts`, `manifest.json`, `public/brand/*.png` and the e-mail header PNG. `--check` (CI) fails when a generated text file is stale. `src/lib/__tests__/brand-assets.test.ts` fails on a file not listed in `manifest.json` or on a removed shape coming back.

| File                                               | Use                                                          |
| -------------------------------------------------- | ------------------------------------------------------------ |
| `symbol.svg`, `symbol-32.svg`, `symbol-16.svg`     | symbol master and its small cuts (tile-less, `currentColor`) |
| `wordmark.svg`, `lockup.svg`, `lockup-stacked.svg` | wordmark and lockups                                         |
| `favicon-16.svg`, `favicon-32.svg`                 | dedicated favicon drawings on the ink tile                   |
| `app-icon.svg`, `maskable-512.svg`                 | app icon (apple icon, manifest)                              |
| `og-image.svg`                                     | 1200 x 630 social image                                      |

Rules: the symbol at 24 px or less uses the 16 px cut, up to 40 px the 32 px cut, above that the master. Clear space is one bracket arm (44/104 of the symbol height) on every side. Minimum: horizontal lockup 16 px tall, stacked 40 px, symbol 16 px. Colours: ink `#0A1628` or paper `#FAFAF9` for brackets and name; the marker is the only teal element (`--brand`). Do not centre, move, rotate or recolour the marker, add the other two corners, round the brackets, or re-type the name. White-label instances show their own logo or name; the OpenCTEM lockup is used only when the instance brand is OpenCTEM.

The wordmark is set in Sora (SIL Open Font License 1.1, see `LICENSE-Sora.txt`) and outlined to paths; no font file ships.
