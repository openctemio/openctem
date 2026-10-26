import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { FilterChipsRow, LockedChip, fitChipsRow } from '../filter-chips-row'

// The chips row under a list toolbar. Owner report 2026-10-25 (iPhone, 390px,
// /findings): the locked "Informational hidden / Show" chip was drawn under the
// next chip. The leading block was the row's only shrinkable item, so it was
// squeezed under its content, and the fold counted its squeezed width, so no
// chip was folded to make room.

describe('fitChipsRow', () => {
  // A 390px phone: 358px of row inside the 16px gutters.
  const phone = { total: 358, trail: 96, end: 72 }

  it('shows every chip when everything fits on one line', () => {
    expect(fitChipsRow({ total: 1200, lead: 200, trail: 96, end: 72, chips: [130, 120] })).toEqual({
      fit: 2,
      stacked: false,
    })
  })

  it('folds chips into "+N more" using the leading chip at its natural width', () => {
    // 900 - (200 + 8) - (96 + 8) - (72 + 8) = 508 for chips: two of 200 fit with "+N more".
    expect(
      fitChipsRow({ total: 900, lead: 200, trail: 96, end: 72, chips: [200, 200, 200] })
    ).toEqual({ fit: 2, stacked: false })
  })

  it('puts the leading chip on its own line on a phone, never under a chip', () => {
    // 358 - 208 - 104 - 80 < 0: not even "+N more" fits beside it.
    expect(fitChipsRow({ ...phone, lead: 200, chips: [130] })).toEqual({ fit: 1, stacked: true })
  })

  it('folds the chips on the second line when they do not fit there either', () => {
    // Second line: 358 - 104 - 80 = 174, so one 80px chip and "+N more".
    expect(fitChipsRow({ ...phone, lead: 200, chips: [80, 80, 80] })).toEqual({
      fit: 1,
      stacked: true,
    })
  })

  it('stacks a leading chip with no chips when it and the actions do not fit', () => {
    expect(fitChipsRow({ ...phone, lead: 200, chips: [] })).toEqual({ fit: 0, stacked: true })
    expect(fitChipsRow({ ...phone, lead: 150, chips: [] })).toEqual({ fit: 0, stacked: false })
  })

  it('never stacks without a leading chip', () => {
    expect(fitChipsRow({ ...phone, lead: 0, chips: [130, 130, 130] })).toEqual({
      fit: 0,
      stacked: false,
    })
  })
})

describe('FilterChipsRow measuring', () => {
  const widths = { row: 358, lead: 200, chip: 130, trail: 96, end: 72 }
  let restore: Array<() => void> = []

  function stub(proto: object, prop: string, get: (el: HTMLElement) => number) {
    const original = Object.getOwnPropertyDescriptor(proto, prop)
    Object.defineProperty(proto, prop, {
      configurable: true,
      get(this: HTMLElement) {
        return get(this)
      },
    })
    restore.push(() => {
      if (original) Object.defineProperty(proto, prop, original)
    })
  }

  beforeEach(() => {
    globalThis.ResizeObserver ??= class {
      observe() {}
      unobserve() {}
      disconnect() {}
    } as unknown as typeof ResizeObserver
    stub(HTMLElement.prototype, 'clientWidth', (el) =>
      el.dataset.slot === 'filter-chips-row' ? widths.row : 0
    )
    stub(HTMLElement.prototype, 'offsetWidth', (el) => {
      if (el.dataset.chipKey) return widths.chip
      if (el.parentElement?.dataset.slot === 'filter-chips-leading') return widths.lead
      if (el.dataset.slot === 'filter-chips-trailing') return widths.trail
      if (el.dataset.slot === 'filter-chips-end') return widths.end
      return 0
    })
  })

  afterEach(() => {
    restore.forEach((r) => r())
    restore = []
    vi.restoreAllMocks()
  })

  const row = (chips: string[]) => (
    <FilterChipsRow
      data-testid="row"
      leading={
        <LockedChip actionLabel="Show" onAction={() => {}}>
          Informational hidden (12)
        </LockedChip>
      }
      chips={chips.map((c) => (
        <span key={c}>{c}</span>
      ))}
      trailing={<button type="button">Add filter</button>}
      end={<span>90 findings</span>}
    />
  )

  it('stacks the locked chip above the chips at phone width', () => {
    render(row(['Related to is Me']))
    const r = screen.getByTestId('row')
    expect(r).toHaveAttribute('data-stacked')
    expect(screen.getByText('Related to is Me')).toBeInTheDocument()
  })

  it('keeps one line when the row is wide', () => {
    widths.row = 1200
    try {
      render(row(['Related to is Me', 'EPSS score at least 0.5']))
      expect(screen.getByTestId('row')).not.toHaveAttribute('data-stacked')
      expect(screen.queryByText(/more/)).toBeNull()
    } finally {
      widths.row = 358
    }
  })

  it('folds what does not fit beside the actions on the second line', () => {
    widths.chip = 70
    try {
      render(row(['a', 'b', 'c']))
      // Second line: 358 - 104 - 80 = 174: one 70px chip and "+2 more" (88).
      expect(screen.getByTestId('row')).toHaveAttribute('data-stacked')
      expect(screen.getByText('a')).toBeInTheDocument()
      expect(screen.queryByText('b')).toBeNull()
      expect(screen.getByText('+2 more')).toBeInTheDocument()
    } finally {
      widths.chip = 130
    }
  })
})
