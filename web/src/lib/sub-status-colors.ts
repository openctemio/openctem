/**
 * The colour of an organization's finding sub-status. The API stores a name
 * from a fixed palette of sixteen (api findinglifecycle.Colors), never free
 * CSS. The colour only tints a small dot next to the label: the label carries
 * the meaning. The console shows the ten tag swatch names (lib/tag-colors.ts),
 * so each of the sixteen stored names folds onto one of them here; the stored
 * value is never rewritten.
 */

import { TAG_SWATCH_CLASS, type TagPaletteName } from '@/lib/tag-colors'

/** Stored sub-status colour name -> tag swatch name. */
export const SUB_STATUS_TO_TAG_SWATCH: Record<string, TagPaletteName> = {
  gray: 'grey',
  red: 'red',
  orange: 'orange',
  amber: 'amber',
  yellow: 'yellow',
  lime: 'green',
  green: 'green',
  emerald: 'green',
  teal: 'cyan',
  cyan: 'cyan',
  sky: 'blue',
  blue: 'blue',
  indigo: 'blue',
  violet: 'violet',
  purple: 'violet',
  pink: 'pink',
}

/** The tag swatch name of a stored colour; unknown or missing is grey. */
export function subStatusSwatch(color: string | undefined): TagPaletteName {
  return (color && SUB_STATUS_TO_TAG_SWATCH[color]) || 'grey'
}

/** The dot class of a stored colour name; an unknown name gets the grey swatch. */
export function subStatusDotClass(color: string | undefined): string {
  return TAG_SWATCH_CLASS[subStatusSwatch(color)]
}
