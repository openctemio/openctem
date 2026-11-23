import { layoutMatrix } from '../../../e2e/helpers/layout-breaks'
import { consoleListData } from '../helpers/rich-data'

/**
 * MVP acceptance v2 for the platform console: the routes named in
 * LAYOUT_ROUTES through the same viewport matrix and detectors as the tenant
 * app's spec 75e (e2e/helpers/layout-matrix.ts), signed in with the session
 * the global setup saved and the lists served from CONSOLE_LIST_DATA.
 * Defines no test unless LAYOUT_MATRIX is set:
 *   LAYOUT_MATRIX=v2 LAYOUT_ROUTES=/users,/system/alerts LAYOUT_SWEEP_OUT=<dir> \
 *   CONSOLE_E2E_ELEVATE=1 npx playwright test -c playwright.console.config.ts layout-matrix
 * CONSOLE_E2E_ELEVATE=1 elevates the session once in the global setup, so the
 * pages show their actions as an elevated administrator sees them.
 */
layoutMatrix({ tag: ['@console'], session: 'stored', data: consoleListData })
