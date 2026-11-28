/**
 * Slices of a categorical ring (counts by asset type, by source...): largest
 * first, each with its own colour. The palette has five distinct series
 * colours, so a long tail is folded into one "Other" slice in a neutral
 * colour instead of cycling the palette, where two slices of the same colour
 * could not be told apart. The total never changes: Other carries the sum of
 * what it folds.
 */

export interface CategorySlice {
  /** The category key ("ip_address"), or OTHER_SLICE for the fold. */
  key: string
  name: string
  value: number
  color: string
}

export const OTHER_SLICE = '__other__'

/** The colour of the folded tail: neutral, never one of the series colours. */
export const OTHER_SLICE_COLOR = 'var(--border-strong)'

export function categorySlices(
  counts: Record<string, number> | undefined,
  palette: readonly string[],
  label: (key: string) => string,
  otherLabel: string
): CategorySlice[] {
  const rows = Object.entries(counts ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
  const fits = rows.length <= palette.length
  const head = fits ? rows : rows.slice(0, palette.length - 1)
  const out: CategorySlice[] = head.map(([key, value], i) => ({
    key,
    name: label(key),
    value,
    color: palette[i],
  }))
  if (!fits) {
    const rest = rows.slice(palette.length - 1).reduce((sum, [, n]) => sum + n, 0)
    out.push({ key: OTHER_SLICE, name: otherLabel, value: rest, color: OTHER_SLICE_COLOR })
  }
  return out
}
