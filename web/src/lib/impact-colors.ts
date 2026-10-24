/**
 * CIA IMPACT-RATING levels for OpenCTEM.
 *
 * Impact rating = the CTEM Scoping business impact of losing an asset's
 * Confidentiality / Integrity / Availability (low | moderate | high). It is an
 * ordinal classification, not a severity and not a status, so it renders as a
 * Tag level (bars and a word, research/247) with no hue. Peer to
 * `criticality-colors.ts`.
 */

import type { ImpactRating } from '@/features/assets/types/asset.types'

/** Impact rating -> Tag level (1 to 3 of 4 bars). */
export const IMPACT_RATING_LEVEL: Record<ImpactRating, 1 | 2 | 3> = {
  low: 1,
  moderate: 2,
  high: 3,
}
