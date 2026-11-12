/**
 * The pages the design gate holds to their design boards
 * (docs/development/design-gate.md). One entry per page: the route, the board
 * and the part of it the page must match, the fixture set that reproduces the
 * board's data, and the threshold. The comparison runs at every width and theme
 * listed; the layout pass (Vietnamese, long data, empty data) runs on the same
 * routes.
 *
 * `expected: 'match'` blocks: a comparison above the threshold fails the job.
 * `expected: 'pending'` reports the score and the images but never fails: the
 * page is not migrated to its board yet. Moving an entry to 'match' is the
 * last step of the page's redesign pull request.
 *
 * This file is read by Playwright and by `node scripts/design-reference.mjs`
 * (Node strips the types): keep to type annotations, no enums or namespaces.
 */

export type Theme = 'light' | 'dark'
export type Width = 1440 | 390

export interface DeclaredDifference {
  /** CSS selector on the real page; its box is left out of both images. */
  selector: string
  /** Why the page differs from the board, e.g. the backend item it waits for. */
  reason: string
}

export interface DesignPage {
  id: string
  route: string
  board: {
    /** File name of the board, e.g. P3-Login.dc.html. */
    file: string
    /** SHA-256 of the board file the references were exported from (written by the export script). */
    sha256: string
    /** Selector of the part of the board this page reproduces (one state of the board). */
    crop: string
  }
  page: {
    /** Selector of the matching part of the real page. */
    crop: string
    /** Selector that is visible once the page has its data. */
    ready: string
  }
  fixtures: 'sample'
  widths: Width[]
  themes: Theme[]
  /** `pixel`: colour distance a pixel may have (0..1); `ratio`: share of differing pixels allowed. */
  threshold: { pixel: number; ratio: number }
  expected: 'match' | 'pending'
  /** Extra routes for the layout pass, e.g. the same page with a query that shows more. */
  layoutRoutes?: string[]
  differences?: DeclaredDifference[]
}

/** Defaults: anti-aliasing and font hinting stay under them; one wrong colour, size or missing control does not. */
export const DEFAULT_THRESHOLD = { pixel: 0.1, ratio: 0.02 }

export const MANIFEST: DesignPage[] = [
  {
    id: 'sign-in',
    route: '/login',
    board: {
      file: 'P3-Login.dc.html',
      sha256: '250bb8751d15540e837579ff9ad8cdb35667289b41d06eb17eecff7c96dc1a81',
      crop: '.panes > section.pn:nth-of-type(1) > .ec',
    },
    page: {
      crop: '[data-slot="card"]',
      ready: 'form button[type="submit"]',
    },
    fixtures: 'sample',
    widths: [1440, 390],
    themes: ['light', 'dark'],
    threshold: DEFAULT_THRESHOLD,
    // The sign-in board is the redesign (teal action, providers, notices);
    // the page moves to it in its own pull request.
    expected: 'pending',
    layoutRoutes: ['/login?org=example-corp'],
  },
]
