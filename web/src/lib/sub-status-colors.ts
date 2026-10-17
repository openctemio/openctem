/**
 * The colour of an organization's finding sub-status. The API stores a name
 * from a fixed palette of sixteen (api findinglifecycle.Colors), never free
 * CSS. The colour only tints a small dot next to the label: the label carries
 * the meaning and the pill itself uses theme tokens, so it reads the same in
 * light and dark mode. Sixteen distinct accents are more than the semantic
 * tokens provide, hence the palette classes below (one place, reviewed).
 */

export const SUB_STATUS_DOT_CLASS: Record<string, string> = {
  gray: 'bg-gray-500', // palette-ok: organization label palette (16 distinct accents)
  red: 'bg-red-500', // palette-ok: organization label palette (16 distinct accents)
  orange: 'bg-orange-500', // palette-ok: organization label palette (16 distinct accents)
  amber: 'bg-amber-500', // palette-ok: organization label palette (16 distinct accents)
  yellow: 'bg-yellow-500', // palette-ok: organization label palette (16 distinct accents)
  lime: 'bg-lime-500', // palette-ok: organization label palette (16 distinct accents)
  green: 'bg-green-500', // palette-ok: organization label palette (16 distinct accents)
  emerald: 'bg-emerald-500', // palette-ok: organization label palette (16 distinct accents)
  teal: 'bg-teal-500', // palette-ok: organization label palette (16 distinct accents)
  cyan: 'bg-cyan-500', // palette-ok: organization label palette (16 distinct accents)
  sky: 'bg-sky-500', // palette-ok: organization label palette (16 distinct accents)
  blue: 'bg-blue-500', // palette-ok: organization label palette (16 distinct accents)
  indigo: 'bg-indigo-500', // palette-ok: organization label palette (16 distinct accents)
  violet: 'bg-violet-500', // palette-ok: organization label palette (16 distinct accents)
  purple: 'bg-purple-500', // palette-ok: organization label palette (16 distinct accents)
  pink: 'bg-pink-500', // palette-ok: organization label palette (16 distinct accents)
}

/** The dot class of a palette name; an unknown name gets the muted token. */
export function subStatusDotClass(color: string | undefined): string {
  return (color && SUB_STATUS_DOT_CLASS[color]) || 'bg-muted-foreground'
}
