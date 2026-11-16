import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { FilterChipsRow, LockedChip, fitChipsRow } from '../filter-chips-row'

// The chips row under a list toolbar. Owner report 2026-10-25 (iPhone, 390px,
// /findings): the locked "Informational hidden / Show" chip was drawn under the
// next chip. The leading block was the row's only shrinkable item, so it was
// squeezed under its content, and the fold counted its squeezed width, so no
// chip was folded to make room.

describe('fitChipsRow', () => {
  it('shows every chip when everything fits on one line', () => {
    expect(fitChipsRow({ total: 1200, lead: 200, end: 168, chips: [130, 120] })).toEqual({ fit: 2 })
  })

  it('folds chips into "+N more" beside the leading chip and the end block', () => {
    // 900 - (200 + 8) - (168 + 8) = 516 for chips: two of 200 fit with "+N more".
    expect(fitChipsRow({ total: 900, lead: 200, end: 168, chips: [200, 200, 200] })).toEqual({
      fit: 2,
    })
  })

  it('never asks for a second line: with no room every chip folds', () => {
    // 358 - 208 - 176 < 0: only "+N more" is left, on the same line.
    expect(fitChipsRow({ total: 358, lead: 200, end: 168, chips: [130] })).toEqual({ fit: 0 })
    expect(fitChipsRow({ total: 358, lead: 0, end: 168, chips: [80, 80, 80] })).toEqual({ fit: 1 })
  })

  it('keeps the fit whatever the end block holds once measured (Clear pinned at the end)', () => {
    const a = fitChipsRow({ total: 1000, lead: 0, end: 200, chips: [120, 120, 120, 120] })
    const b = fitChipsRow({ total: 1000, lead: 0, end: 200, chips: [120, 120, 120, 120, 120] })
    expect(b.fit).toBeLessThanOrEqual(5)
    expect(a.fit).toBe(4)
  })
})

describe('FilterChipsRow measuring', () => {
  const widths = { row: 358, lead: 200, chip: 130, end: 168 }
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
    />
  )

  it('one line of one height: the locked chip and the chips never stack', () => {
    render(row(['Related to is Me']))
    const r = screen.getByTestId('row')
    expect(r).toHaveClass('flex-nowrap', 'h-control')
    expect(r).not.toHaveClass('flex-wrap')
    // 358 - 208 - 176 leaves no room: the chip folds into "+1 more" on the same line.
    expect(screen.getByText('+1 more')).toBeInTheDocument()
  })

  it('keeps every chip when the row is wide', () => {
    widths.row = 1200
    try {
      render(row(['Related to is Me', 'EPSS score at least 0.5']))
      expect(screen.queryByText(/more/)).toBeNull()
    } finally {
      widths.row = 358
    }
  })

  it('folds what does not fit and pins the list actions and Clear at the end', () => {
    widths.row = 750
    widths.chip = 120
    try {
      render(row(['a', 'b', 'c', 'd']))
      // 750 - 208 - 176 = 366: two 120px chips, a gap and "+2 more" (88) take 340.
      expect(screen.getByText('a')).toBeInTheDocument()
      expect(screen.getByText('b')).toBeInTheDocument()
      expect(screen.queryByText('c')).toBeNull()
      expect(screen.getByText('+2 more')).toBeInTheDocument()
      const end = document.querySelector('[data-slot="filter-chips-end"]') as HTMLElement
      expect(end).toHaveClass('ms-auto')
      expect(end).toHaveTextContent(/^Add filter$/)
    } finally {
      widths.row = 358
      widths.chip = 130
    }
  })

  it('on a phone keeps every chip in a strip that scrolls sideways, never "+N more"', () => {
    const width = window.innerWidth
    widths.chip = 70
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    try {
      render(row(['a', 'b', 'c']))
      for (const c of ['a', 'b', 'c']) expect(screen.getByText(c)).toBeInTheDocument()
      expect(screen.queryByText(/more/)).toBeNull()
      const strip = document.querySelector('[data-slot="filter-chips-strip"]') as HTMLElement
      expect(strip).toHaveAttribute('data-scroll')
      expect(strip).toHaveClass('overflow-x-auto')
      // The locked chip scrolls with the chips: one line.
      expect(strip).toContainElement(screen.getByText('Informational hidden (12)'))
      // The edge fade reads the attributes the scroll hook sets.
      expect(strip.className).toContain('data-[fade-end=true]')
      expect(strip).toHaveAttribute('data-fade-end')
    } finally {
      Object.defineProperty(window, 'innerWidth', { configurable: true, value: width })
      widths.chip = 130
    }
  })
})

describe('FilterChipsRow with nothing to show', () => {
  it('renders nothing without chips, actions, count or leading chip', () => {
    const { container } = render(<FilterChipsRow chips={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('marks a row that holds only its leading chip, so the toolbar can hide it', () => {
    render(<FilterChipsRow data-testid="row" chips={[]} leading={<span />} />)
    expect(screen.getByTestId('row')).toHaveAttribute('data-bare')
  })
})
