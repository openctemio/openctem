/**
 * The fixed palette of a user-chosen tag colour. A colour is stored as its
 * NAME and validated against this list (never a free CSS string, so a tag
 * cannot inject a style). It renders as an 8px dot beside ink text, so text
 * contrast never depends on the chosen colour. Each dot is >= 3:1 on the card
 * in light and dark (src/styles/__tests__/contrast.test.ts). Teal is not in the
 * list: it is the act-here accent.
 */

export const TAG_PALETTE = [
  'red',
  'orange',
  'amber',
  'yellow',
  'green',
  'cyan',
  'blue',
  'violet',
  'pink',
  'grey',
] as const
export type TagPaletteName = (typeof TAG_PALETTE)[number]

/** Dot fill per palette name. Literal classes, so Tailwind generates them. */
export const TAG_SWATCH_CLASS: Record<TagPaletteName, string> = {
  red: 'bg-tag-red',
  orange: 'bg-tag-orange',
  amber: 'bg-tag-amber',
  yellow: 'bg-tag-yellow',
  green: 'bg-tag-green',
  cyan: 'bg-tag-cyan',
  blue: 'bg-tag-blue',
  violet: 'bg-tag-violet',
  pink: 'bg-tag-pink',
  grey: 'bg-tag-grey',
}

/** True when `name` is one of the palette names. */
export function isTagPaletteName(name: unknown): name is TagPaletteName {
  return typeof name === 'string' && (TAG_PALETTE as readonly string[]).includes(name)
}
