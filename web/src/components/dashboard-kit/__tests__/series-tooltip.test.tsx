import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { buildSeriesTooltip, SeriesTooltip, type SeriesTooltipMeta } from '../series-tooltip'
import { formatBucketRange } from '@/lib/format-metric'

const PRIO: SeriesTooltipMeta[] = ['P0', 'P1', 'P2', 'P3'].map((k) => ({
  key: k,
  label: k,
  swatch: `var(--prio-${k.slice(1)})`,
}))

const rows = [
  { t: '2026-10-13T00:00:00Z', P0: 2, P1: 10, P2: 0, P3: 1 },
  { t: '2026-10-20T00:00:00Z', P0: 3, P1: 8, P2: 0, P3: 0 },
]

describe('buildSeriesTooltip', () => {
  it('lists a stack top first, folds zeros, totals and compares with the previous bucket', () => {
    const m = buildSeriesTooltip(rows, '2026-10-20T00:00:00Z', PRIO, 'stack')!
    expect(m.rows.map((r) => [r.key, r.value, r.delta])).toEqual([
      ['P1', 8, -2],
      ['P0', 3, 1],
    ])
    expect(m.zero).toBe(2)
    expect(m.total).toEqual({ value: 11, delta: -2 })
    expect(m.hasPrevious).toBe(true)
  })

  it('has no change on the first bucket', () => {
    const m = buildSeriesTooltip(rows, '2026-10-13T00:00:00Z', PRIO, 'stack')!
    expect(m.rows.every((r) => r.delta === null)).toBe(true)
    expect(m.total?.delta).toBeNull()
    expect(m.hasPrevious).toBe(false)
  })

  it('a series with no point is absent, never 0', () => {
    const m = buildSeriesTooltip([{ t: 'a', P0: 4 }], 'a', PRIO, 'lines')!
    expect(m.rows.map((r) => r.key)).toEqual(['P0'])
    expect(m.zero).toBe(0)
    expect(m.total).toBeNull()
  })

  it('keeps a zero row in a two-series chart', () => {
    const flowMeta = [
      { key: 'opened', label: 'New', swatch: 'var(--viz-div-opened)' },
      { key: 'fixed', label: 'Fixed', swatch: 'var(--viz-div-fixed)' },
    ]
    const m = buildSeriesTooltip(
      [
        { t: 'a', opened: 4, fixed: -6 },
        { t: 'b', opened: 26, fixed: 0 },
      ],
      'b',
      flowMeta,
      'flow'
    )!
    expect(m.rows.map((r) => [r.key, r.value, r.delta])).toEqual([
      ['opened', 26, 22],
      ['fixed', 0, -6],
    ])
    expect(m.net).toBe(26)
    expect(m.total).toBeNull()
  })

  it('returns nothing for an unknown bucket', () => {
    expect(buildSeriesTooltip(rows, 'nope', PRIO, 'stack')).toBeNull()
  })
})

describe('formatBucketRange', () => {
  it('words a week as its seven days, a month by name, a day with its weekday', () => {
    const w = formatBucketRange('2026-10-20T00:00:00Z', 'week', 'en')
    expect(w.kind).toBe('week')
    expect(w.text).toMatch(/Oct 20\s*–\s*26/)
    expect(formatBucketRange('2026-10-01T00:00:00Z', 'month', 'en').text).toBe('October 2026')
    expect(formatBucketRange('2026-10-20T00:00:00Z', 'day', 'en').text).toBe('Tue, Oct 20, 2026')
  })
})

describe('SeriesTooltip', () => {
  it('renders the bucket span, one row per series with value and change, and the total', () => {
    render(
      <SeriesTooltip
        active
        label="2026-10-20T00:00:00Z"
        rows={rows}
        meta={PRIO}
        mode="stack"
        bucket="week"
      />
    )
    const tip = screen.getByTestId('series-tooltip')
    expect(within(tip).getByText(/^Week of Oct 20/)).toBeInTheDocument()
    expect(within(tip).getByText('vs previous')).toBeInTheDocument()
    const p1 = within(tip).getByText('P1').closest('tr')!
    expect(within(p1).getByText('8')).toBeInTheDocument()
    expect(within(p1).getByText('−2')).toBeInTheDocument()
    const total = within(tip).getByText('Total').closest('tr')!
    expect(within(total).getByText('11')).toBeInTheDocument()
    expect(within(tip).getByText('2 more at 0')).toBeInTheDocument()
    // The swatch is the series' palette colour, not a fixed hue.
    const dot = p1.querySelector('span[aria-hidden]') as HTMLElement
    expect(dot.style.background).toBe('var(--prio-1)')
  })

  it('renders nothing while inactive', () => {
    const { container } = render(
      <SeriesTooltip active={false} label="x" rows={rows} meta={PRIO} mode="stack" bucket="week" />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
