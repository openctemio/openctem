/**
 * The colour of a capability. A capability stores the NAME of its colour
 * (api capability.color). The console shows the ten tag swatch names
 * (lib/tag-colors.ts) as a dot beside ink text, so every older stored name
 * folds onto one of them here; the stored value is never rewritten and teal
 * is no longer offered. One map for every capability surface (badge, card,
 * table, detail panel, create and edit dialogs).
 */

import { TAG_PALETTE, type TagPaletteName } from '@/lib/tag-colors'

/** Stored capability colour name -> tag swatch name. */
export const CAPABILITY_COLOR_TO_SWATCH: Record<string, TagPaletteName> = {
  blue: 'blue',
  purple: 'violet',
  violet: 'violet',
  indigo: 'blue',
  sky: 'blue',
  green: 'green',
  lime: 'green',
  emerald: 'green',
  red: 'red',
  orange: 'orange',
  cyan: 'cyan',
  teal: 'cyan',
  yellow: 'yellow',
  amber: 'amber',
  pink: 'pink',
  fuchsia: 'pink',
  rose: 'pink',
  gray: 'grey',
  grey: 'grey',
  slate: 'grey',
}

/** The swatch name of a stored colour; unknown or missing is grey. */
export function capabilitySwatch(color: string | undefined | null): TagPaletteName {
  return (color && CAPABILITY_COLOR_TO_SWATCH[color]) || 'grey'
}

/** The colours a capability author can choose: the ten swatch names. */
export const CAPABILITY_COLOR_CHOICES: readonly TagPaletteName[] = TAG_PALETTE
