/**
 * Centralized CRITICALITY color system for OpenCTEM.
 *
 * Criticality = business importance of an asset / service. It is a SEPARATE
 * scale from finding severity: **low criticality is GOOD**, so `low` is GREEN
 * here (vs blue in severity-colors.ts), and `none` (Not rated) is neutral.
 * Critical, high and medium share the severity tokens, so the same hue means
 * the same urgency on every page. The scale itself (values, order, labels) is
 * criticality.ts.
 *
 * ALL components must import criticality colors from here instead of defining
 * their own inline maps.
 */

import type { CriticalityLevel } from '@/lib/criticality'
import {
  SEVERITY_BADGE_SOFT,
  SEVERITY_CHART_COLORS,
  SEVERITY_DOT_COLORS,
  SEVERITY_TEXT_COLORS,
} from '@/lib/severity-colors'

export type { CriticalityLevel }

/** Soft-tint badge (the scoping/asset default): translucent fill + hued text. */
export const CRITICALITY_BADGE_SOFT: Record<CriticalityLevel, string> = {
  critical: SEVERITY_BADGE_SOFT.critical,
  high: SEVERITY_BADGE_SOFT.high,
  medium: SEVERITY_BADGE_SOFT.medium,
  low: 'bg-success/10 text-success border-success/30',
  none: 'bg-muted text-muted-foreground border-border',
}

/** Light pill (for lists/tables): the same tints as the soft badge. */
export const CRITICALITY_BADGE_LIGHT: Record<CriticalityLevel, string> = CRITICALITY_BADGE_SOFT

/** Inline text color. */
export const CRITICALITY_TEXT_COLORS: Record<CriticalityLevel, string> = {
  critical: SEVERITY_TEXT_COLORS.critical,
  high: SEVERITY_TEXT_COLORS.high,
  medium: SEVERITY_TEXT_COLORS.medium,
  low: 'text-success',
  none: 'text-muted-foreground',
}

/** Dot/indicator background token. */
export const CRITICALITY_DOT_COLORS: Record<CriticalityLevel, string> = {
  critical: SEVERITY_DOT_COLORS.critical,
  high: SEVERITY_DOT_COLORS.high,
  medium: SEVERITY_DOT_COLORS.medium,
  low: 'bg-success',
  none: 'bg-muted-foreground',
}

/** Chart colors (CSS variables). */
export const CRITICALITY_CHART_COLORS: Record<CriticalityLevel, string> = {
  critical: SEVERITY_CHART_COLORS.critical,
  high: SEVERITY_CHART_COLORS.high,
  medium: SEVERITY_CHART_COLORS.medium,
  low: 'var(--success)',
  none: SEVERITY_CHART_COLORS.info,
}
