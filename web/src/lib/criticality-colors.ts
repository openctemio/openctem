/**
 * Centralized CRITICALITY color system for OpenCTEM.
 *
 * Criticality = business importance of an asset / service. It is a SEPARATE
 * scale from finding severity: **low criticality is GOOD**, so `low` is GREEN
 * here (vs blue in severity-colors.ts), and `none` (Not rated) is neutral.
 * The scale itself (values, order, labels) is criticality.ts.
 *
 * ALL components must import criticality colors from here instead of defining
 * their own inline maps.
 */

import type { CriticalityLevel } from '@/lib/criticality'

export type { CriticalityLevel }

/** Soft-tint badge (the scoping/asset default): translucent fill + hued text. */
export const CRITICALITY_BADGE_SOFT: Record<CriticalityLevel, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20 dark:bg-red-900/30 dark:text-red-400',
  high: 'bg-orange-500/10 text-orange-500 border-orange-500/20 dark:bg-orange-900/30 dark:text-orange-400',
  medium:
    'bg-yellow-500/10 text-yellow-500 border-yellow-500/20 dark:bg-yellow-900/30 dark:text-yellow-400',
  low: 'bg-green-500/10 text-green-500 border-green-500/20 dark:bg-green-900/30 dark:text-green-400',
  none: 'bg-muted text-muted-foreground border-border',
}

/** Light pill (solid-ish, for lists/tables). */
export const CRITICALITY_BADGE_LIGHT: Record<CriticalityLevel, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-400',
  high: 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-400',
  medium:
    'bg-yellow-100 text-yellow-900 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-400',
  low: 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-400',
  none: 'bg-muted text-muted-foreground border-border',
}

/** Inline text color. */
export const CRITICALITY_TEXT_COLORS: Record<CriticalityLevel, string> = {
  critical: 'text-red-500 dark:text-red-400',
  high: 'text-orange-500 dark:text-orange-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  low: 'text-green-600 dark:text-green-400',
  none: 'text-muted-foreground',
}

/** Dot/indicator background token. */
export const CRITICALITY_DOT_COLORS: Record<CriticalityLevel, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  none: 'bg-muted-foreground',
}

/** Chart hex colors. */
export const CRITICALITY_CHART_COLORS: Record<CriticalityLevel, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  none: '#94a3b8',
}
