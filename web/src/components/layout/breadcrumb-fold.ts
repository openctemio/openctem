/**
 * How the header breadcrumb shortens (design "Header breadcrumb", settled on
 * the canvas 2026-11-13). The trail is home, the ancestor levels, then the
 * current page. As the screen narrows:
 *
 * 1. the current page truncates with an ellipsis at 32 characters, its full
 *    name in a tooltip (CSS, not here);
 * 2. below 1280px the middle levels fold into a "…" menu, so home, the first
 *    level, the parent and the current page stay;
 * 3. below 1024px only home, the parent and the current page stay (the first
 *    level folds into the same menu);
 * 4. below 768px the header shows no breadcrumb; a detail page shows its way
 *    up as a "‹ Parent" link in the page header.
 *
 * Folding is by the viewport breakpoints of steps 2 and 3, so the result is a
 * plan of CSS classes per level, computed here once and tested as a pure
 * function. Ancestors that still do not fit shrink (truncate) before the
 * current page does.
 */

export type CrumbRole = 'first' | 'middle' | 'parent' | 'current'

export interface PlannedCrumb<T> {
  item: T
  role: CrumbRole
  /** Shown in the trail from this breakpoint up (`always`: at every width the trail shows). */
  showFrom: 'always' | 'lg' | 'xl'
}

export interface CrumbPlan<T> {
  crumbs: PlannedCrumb<T>[]
  /** Levels the "…" menu offers, each with the width below which it is in the menu. */
  folded: { item: T; foldedBelow: 'lg' | 'xl' }[]
  /** Below which width the "…" menu shows (none when nothing ever folds). */
  menuBelow: 'lg' | 'xl' | null
}

/** `levels` are the ancestors (outermost first), `current` the page itself. */
export function planCrumbs<T>(levels: T[], current: T): CrumbPlan<T> {
  const crumbs: PlannedCrumb<T>[] = []
  const folded: CrumbPlan<T>['folded'] = []
  const n = levels.length
  levels.forEach((item, i) => {
    if (i === n - 1) {
      crumbs.push({ item, role: 'parent', showFrom: 'always' })
    } else if (i === 0) {
      crumbs.push({ item, role: 'first', showFrom: 'lg' })
      folded.push({ item, foldedBelow: 'lg' })
    } else {
      crumbs.push({ item, role: 'middle', showFrom: 'xl' })
      folded.push({ item, foldedBelow: 'xl' })
    }
  })
  crumbs.push({ item: current, role: 'current', showFrom: 'always' })
  const menuBelow = folded.some((f) => f.foldedBelow === 'xl')
    ? 'xl'
    : folded.length > 0
      ? 'lg'
      : null
  return { crumbs, folded, menuBelow }
}

/** The levels visible at a viewport width (for tests and the e2e check). */
export function visibleAt<T>(plan: CrumbPlan<T>, widthPx: number): T[] {
  const shown = (from: PlannedCrumb<T>['showFrom']) =>
    from === 'always' || (from === 'lg' && widthPx >= 1024) || (from === 'xl' && widthPx >= 1280)
  return plan.crumbs.filter((c) => shown(c.showFrom)).map((c) => c.item)
}

/**
 * The trail's sizes, measured in the page: the room the trail has, the
 * home link, one separator with the gaps around it, the "…" menu button,
 * each ancestor's label at full width and the current page's (at most its
 * 32 characters).
 */
export interface CrumbSizes {
  available: number
  home: number
  /** A separator and the two gaps beside it. */
  step: number
  menu: number
  levels: number[]
  current: number
}

/**
 * Which ancestors fold into the "…" menu so the trail fits its room, by
 * measured width rather than by breakpoint. The middle levels fold first
 * (outermost first), then the first level, and last the parent, so the
 * current page keeps its name; nothing folds while the whole trail fits.
 * Returns the indexes of the folded ancestors, outermost first. When even
 * the current page alone does not fit, it truncates (CSS) with its full
 * name as a tooltip.
 */
export function fitCrumbs(sizes: CrumbSizes): number[] {
  const { available, home, step, menu, levels, current } = sizes
  const n = levels.length
  const order = [
    ...Array.from({ length: Math.max(0, n - 2) }, (_, i) => i + 1),
    ...(n >= 2 ? [0] : []),
    ...(n >= 1 ? [n - 1] : []),
  ]
  const width = (folded: ReadonlySet<number>) =>
    home +
    step +
    current +
    levels.reduce((sum, w, i) => (folded.has(i) ? sum : sum + step + w), 0) +
    (folded.size > 0 ? step + menu : 0)
  const folded = new Set<number>()
  // Half a pixel of rounding per level never folds a trail that fits.
  const room = available + 0.5 * (n + 1)
  for (const i of order) {
    if (width(folded) <= room) break
    folded.add(i)
  }
  return [...folded].sort((a, b) => a - b)
}
