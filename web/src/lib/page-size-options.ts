/**
 * Rows per page of every list: one set (25, 50, 100) and one default (25).
 * A list opened with another size (an older link's ?per_page=20) keeps it.
 */
export const TABLE_PAGE_SIZES = [25, 50, 100] as const
export const DEFAULT_TABLE_PAGE_SIZE = 25

/**
 * The page sizes a page-size select offers, always including the one in use:
 * a list opened at a size outside the defaults (a URL ?per_page=25, a page
 * whose API pages by 25) would otherwise show an empty select.
 */
export function pageSizeChoices(options: readonly number[], current: number): number[] {
  const all = options.includes(current) || !(current > 0) ? [...options] : [...options, current]
  return all.sort((a, b) => a - b)
}
