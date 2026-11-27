import { describe, expect, it } from 'vitest'
import { fitCrumbs, planCrumbs, visibleAt } from '../breadcrumb-fold'

const trail = (n: number) => Array.from({ length: n }, (_, i) => `L${i + 1}`)

describe('planCrumbs', () => {
  it('keeps every level from 1280px', () => {
    const plan = planCrumbs(trail(4), 'Current')
    expect(visibleAt(plan, 1440)).toEqual(['L1', 'L2', 'L3', 'L4', 'Current'])
    expect(visibleAt(plan, 1280)).toEqual(['L1', 'L2', 'L3', 'L4', 'Current'])
  })

  it('folds the middle levels first below 1280px: first, parent and current stay', () => {
    const plan = planCrumbs(trail(4), 'Current')
    expect(visibleAt(plan, 1279)).toEqual(['L1', 'L4', 'Current'])
    expect(visibleAt(plan, 1024)).toEqual(['L1', 'L4', 'Current'])
    expect(plan.menuBelow).toBe('xl')
    expect(plan.folded).toEqual([
      { item: 'L1', foldedBelow: 'lg' },
      { item: 'L2', foldedBelow: 'xl' },
      { item: 'L3', foldedBelow: 'xl' },
    ])
  })

  it('keeps only the parent and the current page below 1024px', () => {
    const plan = planCrumbs(trail(4), 'Current')
    expect(visibleAt(plan, 1023)).toEqual(['L4', 'Current'])
    expect(visibleAt(plan, 768)).toEqual(['L4', 'Current'])
  })

  it('two levels: the first folds only below 1024px', () => {
    const plan = planCrumbs(trail(2), 'Current')
    expect(plan.menuBelow).toBe('lg')
    expect(visibleAt(plan, 1100)).toEqual(['L1', 'L2', 'Current'])
    expect(visibleAt(plan, 900)).toEqual(['L2', 'Current'])
  })

  it('one level or none: nothing folds, no menu', () => {
    expect(planCrumbs(trail(1), 'Current')).toMatchObject({ menuBelow: null, folded: [] })
    expect(visibleAt(planCrumbs(trail(1), 'Current'), 800)).toEqual(['L1', 'Current'])
    expect(visibleAt(planCrumbs([], 'Current'), 800)).toEqual(['Current'])
  })

  it('never folds the parent or the current page', () => {
    for (const n of [1, 2, 3, 6])
      for (const w of [768, 1023, 1024, 1279, 1280, 2560]) {
        const v = visibleAt(planCrumbs(trail(n), 'Current'), w)
        expect(v.slice(-2)).toEqual([`L${n}`, 'Current'])
      }
  })
})

describe('fitCrumbs (by measured width)', () => {
  // home 16, a step (separator + gaps) 34, the menu 24.
  const sizes = (available: number, levels: number[], current = 120) => ({
    available,
    home: 16,
    step: 34,
    menu: 24,
    levels,
    current,
  })
  // The whole trail: 16 + 34 + 120 + 3 x (34 + 100) = 572.

  it('folds nothing while the whole trail fits', () => {
    expect(fitCrumbs(sizes(572, [100, 100, 100]))).toEqual([])
    expect(fitCrumbs(sizes(2000, [100, 100, 100, 100]))).toEqual([])
  })

  it('folds the middle levels first, then the first, then the parent', () => {
    // Without the middle (and with the menu): 572 - 134 + 58 = 496.
    expect(fitCrumbs(sizes(560, [100, 100, 100]))).toEqual([1])
    expect(fitCrumbs(sizes(496, [100, 100, 100]))).toEqual([1])
    // Without the first too: 362.
    expect(fitCrumbs(sizes(400, [100, 100, 100]))).toEqual([0, 1])
    // Only the current page beside home and the menu: 228.
    expect(fitCrumbs(sizes(300, [100, 100, 100]))).toEqual([0, 1, 2])
    expect(fitCrumbs(sizes(100, [100, 100, 100]))).toEqual([0, 1, 2])
  })

  it('folds the outer middle level before the inner one', () => {
    const levels = [80, 80, 80, 80]
    const all = 16 + 34 + 120 + 4 * (34 + 80)
    expect(fitCrumbs(sizes(all - 10, levels))).toEqual([1])
    expect(fitCrumbs(sizes(500, levels))).toEqual([1, 2])
  })

  it('folds the parent last: names that would be cut fold instead', () => {
    const levels = [70, 90] // "Khám phá", "Cần chú ý"
    expect(fitCrumbs(sizes(400, levels, 150))).toEqual([0])
    // vi at 1024 with the sidebar open: about 260 px for the trail.
    expect(fitCrumbs(sizes(260, levels, 150))).toEqual([0, 1])
  })

  it('one level: it folds only when the current page needs its room', () => {
    expect(fitCrumbs(sizes(400, [100]))).toEqual([])
    expect(fitCrumbs(sizes(250, [100]))).toEqual([0])
    expect(fitCrumbs(sizes(100, []))).toEqual([])
  })
})
