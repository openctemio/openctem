# Design gate: pages held to their design boards

The design gate keeps a shipped page equal to its approved design board. It is a Playwright project
(`web/playwright.design.config.ts`, specs in `web/e2e/design/`) and a CI workflow
(`.github/workflows/web-design-gate.yml`, check `Design gate OK`). Only pages listed in the manifest are
checked; a page joins the manifest in the pull request that moves it to its board.

## How it works

1. **Manifest** (`web/e2e/design/manifest.ts`): one entry per page with the route, the board file and its
   SHA-256, the part of the board the page reproduces (`board.crop`, one state of the board), the matching
   part of the page (`page.crop`), the fixture set, the widths (1440, 390), the themes (light, dark), the
   threshold, `expected` and any declared differences.
2. **References** (`web/e2e/design/references/<id>/<width>-<theme>.png`): the board's crop, exported by
   `web/scripts/design-reference.mjs`. They change only when someone exports them again, so a design change
   reaches a page as a visible image diff and a changed board hash in review.
3. **Fixtures** (`web/e2e/design/fixtures/`): `sample-data.ts` is the design's sample dataset, typed
   (organization "Example Corp", today 11 Nov 2026, the findings table); `api.ts` maps API routes to
   answers for the sets `sample`, `long` and `empty`. A mock API on 127.0.0.1 serves them and is the web
   server's backend, so server-rendered reads and browser calls get the same data. A route without a
   fixture answers 404 and fails a `match` entry: add the fixture.
4. **Reference pass** (`reference.design.ts`): the real page with the `sample` set, the date fixed, motion
   off, fonts loaded and every request outside the web server refused, cropped and compared with the
   reference. Expected, actual and diff images go into the `design-gate` artifact; the job summary lists
   every score.
5. **Layout pass** (`layout.design.ts`): every manifest route (plus `layoutRoutes`) in Vietnamese with the
   `long` and `empty` sets at each width. It fails on sideways page scroll, text clipped by its box (an
   ellipsis or line clamp is allowed; text pushed past the edge of a card or dialog is not), a control whose
   text spills out of it, and two controls that overlap (a button drawn inside a field, such as show
   password, is allowed). It blocks for every entry, pending or not.

## Thresholds

A pixel differs when its colour distance (YIQ, brightness weighted about twice hue) is above
`threshold.pixel` and no pixel within one pixel in the other image is close: anti-aliasing and a sub-pixel
text shift do not count, a moved, recoloured or missing element counts in full. Images of different sizes
are compared on the larger canvas, so a page taller than its board fails by the extra area.
`threshold.ratio` is the share of differing pixels allowed.

Defaults (`DEFAULT_THRESHOLD`): `pixel` 0.1 and `ratio` 0.02 (2%). Measured on the sign-in reference:
a one-pixel shift of the whole image scores 0.36%, a two-pixel shift 10.8%, one recoloured 380 x 36 button
4%. `compare.design.ts` holds these cases as tests. Raise a page's ratio only with a reason in the review.

`expected: 'match'` fails the job above the threshold. `expected: 'pending'` reports the score and images
and never fails: the page has not moved to its board yet.

## Run it

```bash
cd web
npx playwright test -c playwright.design.config.ts            # start next dev on 3100 and a mock API on 3199
DESIGN_WEB_PORT=4100 DESIGN_MOCK_PORT=4199 npx playwright test -c playwright.design.config.ts
npx playwright show-report test-results-design/report         # expected, actual and diff per comparison
```

A dev server you started yourself on the web port is reused; start it with
`BACKEND_API_URL=http://127.0.0.1:<mock port>` so it reads from the mock.

## Add a page

1. Add the entry to `manifest.ts` (`expected: 'pending'` while the page is being built), with `board.crop`
   naming the board state the page shows and `page.crop` the matching element.
2. Add the fixtures the page calls to `fixtures/api.ts`, with values from the design's sample dataset; add
   long and empty variants.
3. Export the references (below) and run the gate. When the page matches, set `expected: 'match'` in the
   same pull request.

## Update a reference

When the board changes, export again from the board files (they live outside the repository):

```bash
cd web
node scripts/design-reference.mjs --board <boards>/P3-Login.dc.html --runtime <boards>/support.js
```

It renders every entry that uses that board at its widths and themes, replaces the PNGs and writes the
board's new SHA-256 into the entry. The board's font links are answered with `web/public/fonts`, the same
files the app serves, and nothing else leaves the machine. Commit the images and the manifest change
together; the reviewer sees the old and new images and the hash change.

## Declare a difference

When the page must differ from the board (the board shows a feature the backend does not have yet), add to
the entry:

```ts
differences: [
  {
    selector: '[data-slot="second-approver"]',
    reason: 'board shows a second approver; backend item B-GA not built',
  },
]
```

The element's box is left out of both images. Remove the difference when the reason no longer holds.

## Security

Fixtures hold only the design's sample data: `example.com` names, documentation address ranges, made-up
people, no secrets. The job needs no token beyond reading the repository, no API, database or images, and
its browser reaches only the web server on 127.0.0.1.
