/**
 * Every link from the console to the documentation site (docs.openctem.io,
 * built from the openctemio/docs repository). Link to the docs only through
 * this module, with full literal URLs: CI (scripts/check_docs_links.py)
 * checks each one against the docs site, page and anchor, so a renamed page
 * or heading fails the build instead of sending users to a 404.
 *
 * Pages use pretty permalinks: `scanning/tools.md` is `/scanning/tools/`.
 */

/** The docs site origin: docs links from the API must start with it. */
export const DOCS_ORIGIN = 'https://docs.openctem.io'

/** The documentation home (sidebar Help menu, About, command menu). */
export const DOCS_URL = 'https://docs.openctem.io'

export const DOCS = {
  ci: {
    guide: 'https://docs.openctem.io/scanning/ci-integration/',
  },
  scanning: {
    scannerContent: 'https://docs.openctem.io/scanning/tools/#scanner-content',
  },
  sensors: {
    transportPlatform: 'https://docs.openctem.io/sensors/transport/#what-the-platform-offers',
  },
} as const
