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

/** The largest `per_page` a list endpoint returns (the API caps a larger one). */
export const MAX_TABLE_PAGE_SIZE = 100

/**
 * A phone list has no numbered pager: "Show 25 more" grows the page size by
 * one step (25, 50, 75, 100), so a multiple of the step up to the API's cap
 * is a page size every list accepts from a link, beside the sizes it offers.
 */
export const PHONE_PAGE_STEP = DEFAULT_TABLE_PAGE_SIZE

export function isPhonePageSize(size: number): boolean {
  return (
    Number.isInteger(size) &&
    size > 0 &&
    size <= MAX_TABLE_PAGE_SIZE &&
    size % PHONE_PAGE_STEP === 0
  )
}

/**
 * The page size after one more step, or null when `current` is already at
 * `max`. A size between two steps (an older link's 20) moves to the next
 * step; the last step stops at `max`.
 */
export function nextPhonePageSize(current: number, max: number = Infinity): number | null {
  if (!(current > 0)) return Math.min(PHONE_PAGE_STEP, max)
  if (current >= max) return null
  return Math.min((Math.floor(current / PHONE_PAGE_STEP) + 1) * PHONE_PAGE_STEP, max)
}
