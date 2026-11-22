import { layoutMatrix } from '../helpers/layout-breaks'

/**
 * MVP acceptance v2 (agent-ops/ui-v2/MVP-ACCEPTANCE.md): the routes named in
 * LAYOUT_ROUTES through the full viewport matrix with the v2 detectors
 * (helpers/layout-matrix.ts). Defines no test unless LAYOUT_MATRIX is set:
 *   LAYOUT_MATRIX=v2 LAYOUT_ROUTES=/my-work,/findings/[id] LAYOUT_SWEEP_OUT=<dir>
 * LAYOUT_MATRIX=ci runs the reduced widths (390, 1024, 1440, 1920).
 */
layoutMatrix({ tag: ['@phone', '@shell'] })
