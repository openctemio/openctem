import { describe, expect, it } from 'vitest'
import { planCrumbs, visibleAt } from '../breadcrumb-fold'

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
