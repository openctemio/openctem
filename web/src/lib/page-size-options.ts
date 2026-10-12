/**
 * The page sizes a page-size select offers, always including the one in use:
 * a list opened at a size outside the defaults (a URL ?per_page=25, a page
 * whose API pages by 25) would otherwise show an empty select.
 */
export function pageSizeChoices(options: readonly number[], current: number): number[] {
  const all = options.includes(current) || !(current > 0) ? [...options] : [...options, current]
  return all.sort((a, b) => a - b)
}
