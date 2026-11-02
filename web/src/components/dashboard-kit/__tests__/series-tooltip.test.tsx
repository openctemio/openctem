import { describe, expect, it } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import fs from 'node:fs'
import path from 'node:path'
import type { Polarity } from '../types'
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

describe('SeriesTooltip change tones', () => {
  const tip = (polarity?: Polarity, mode: 'stack' | 'flow' = 'stack', r = rows, m = PRIO) =>
    render(
      <SeriesTooltip
        active
        label="2026-10-20T00:00:00Z"
        rows={r}
        meta={m}
        mode={mode}
        bucket="week"
        polarity={polarity}
      />
    )
  /** The delta cell (column 4) of a row, or its value cell (column 3) for the net row. */
  const cell = (name: string, col = 3) =>
    (screen.getByText(name).closest('tr')!.cells as HTMLCollectionOf<HTMLTableCellElement>)[col]

  it('lower is better: a rise is red, a drop green, with words for screen readers', () => {
    tip('down_good')
    const rise = cell('P0')
    expect(rise).toHaveClass('text-destructive')
    expect(rise.textContent).toContain('(worse)')
    const drop = cell('P1')
    expect(drop).toHaveClass('text-success')
    expect(drop.textContent).toContain('(better)')
    expect(cell('Total')).toHaveClass('text-success')
  })

  it('higher is better flips the colours and keeps the sign', () => {
    tip('up_good')
    expect(cell('P0')).toHaveClass('text-success')
    expect(cell('P1')).toHaveClass('text-destructive')
  })

  it('neutral or no polarity stays muted with no verdict words', () => {
    tip('neutral')
    const c = cell('P1')
    expect(c).toHaveClass('text-muted-foreground')
    expect(c.textContent).toBe('−2')
    cleanup()
    tip(undefined)
    expect(cell('P1')).toHaveClass('text-muted-foreground')
  })

  it('zero change is muted "unchanged"; a missing previous bucket shows nothing', () => {
    const r = [
      { t: 'a', P0: 2, P1: 5 },
      { t: 'b', P0: 2, P1: 5 },
    ]
    render(
      <SeriesTooltip
        active
        label="b"
        rows={r}
        meta={PRIO}
        mode="stack"
        bucket="week"
        polarity="down_good"
      />
    )
    const z = cell('P0')
    expect(z).toHaveClass('text-muted-foreground')
    expect(z.textContent).toContain('(unchanged)')
    cleanup()
    render(
      <SeriesTooltip
        active
        label="a"
        rows={r}
        meta={PRIO}
        mode="stack"
        bucket="week"
        polarity="down_good"
      />
    )
    expect(screen.queryByText(/better|worse|unchanged/)).toBeNull()
  })

  it('a flow colours opened by the polarity, fixed by its opposite, and the net row', () => {
    const flow = [
      { t: 'a', opened: 5, fixed: -4 },
      { t: 'b', opened: 9, fixed: -10 },
    ]
    const m = [
      { key: 'opened', label: 'Opened', swatch: 'red' },
      { key: 'fixed', label: 'Fixed', swatch: 'green' },
    ]
    render(
      <SeriesTooltip
        active
        label="b"
        rows={flow}
        meta={m}
        mode="flow"
        bucket="week"
        polarity="down_good"
      />
    )
    expect(cell('Opened')).toHaveClass('text-destructive')
    expect(cell('Fixed')).toHaveClass('text-success')
    expect(cell('Net change', 2)).toHaveClass('text-success')
    expect(cell('Net change', 2).textContent).toContain('−1')
  })

  it('every chart passes a polarity to the tooltip', () => {
    const dir = path.resolve(__dirname, '..')
    const viz = fs.readFileSync(path.join(dir, 'series-viz.tsx'), 'utf8')
    const calls = viz.match(/\.\.\.tooltipProps\([^)]*\)/g) ?? []
    expect(calls).toHaveLength(3)
    for (const c of calls) expect(c).toMatch(/polarity\s*\)$/)
    const view = fs.readFileSync(
      path.resolve(dir, '../../features/dashboards/components/widget-view.tsx'),
      'utf8'
    )
    for (const tag of ['DivergingViz', 'ColumnViz', 'AreaLineViz']) {
      expect(view).toMatch(new RegExp(`<${tag}[^>]*polarity=`))
    }
  })
})
