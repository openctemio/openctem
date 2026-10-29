import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { StatViz, ProgressViz } from '../stat-viz'
import { BarViz, barRows } from '../bar-viz'
import { ColumnViz, DivergingViz, netOf, toRows } from '../series-viz'
import { HeatmapViz, ItemsViz, heatStep } from '../grid-viz'
import { LoopViz } from '../loop-viz'
import type { CategoryResult, TimeSeriesResult } from '../types'

describe('StatViz', () => {
  it('shows the value, a polarity-aware change in words and the target chip', () => {
    render(
      <StatViz
        result={{ shape: 'scalar', value: 31, previous: 43, target: { op: '<=', value: 0 } }}
        polarity="down_good"
        href="/findings?state=open&priority_class=P0,P1"
      />
    )
    const link = screen.getByRole('link', { name: '31' })
    expect(link).toHaveAttribute('href', '/findings?state=open&priority_class=P0,P1')
    const delta = screen.getByText('−12').closest('p')!
    expect(delta).toHaveAttribute('data-tone', 'better')
    expect(within(delta).getByText('vs 43 previous period')).toBeInTheDocument()
    expect(within(delta).getByText('(better)')).toBeInTheDocument()
    const chip = screen.getByText('target <= 0').closest('span[data-status]')!
    expect(chip).toHaveAttribute('data-status', 'missed')
    expect(within(chip as HTMLElement).getByText('off target')).toBeInTheDocument()
  })

  it('a rise in a down-is-good figure reads worse', () => {
    render(<StatViz result={{ shape: 'scalar', value: 9, previous: 7 }} polarity="down_good" />)
    expect(screen.getByText('+2').closest('p')).toHaveAttribute('data-tone', 'worse')
  })

  it('a null value is a dash, never 0, and gets no change', () => {
    render(<StatViz result={{ shape: 'scalar', value: null, previous: 4 }} polarity="down_good" />)
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('vs previous period')).toBeNull()
  })

  it('ignores an off-site link', () => {
    render(<StatViz result={{ shape: 'scalar', value: 3 }} href="//evil.example.com" />)
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('durations show median, p90 and sample', () => {
    render(
      <StatViz
        result={{ shape: 'duration', median: 132, p90: 408, n: 37, previous_median: 160.8 }}
        polarity="down_good"
      />
    )
    expect(screen.getByText('5.5 days')).toBeInTheDocument()
    expect(screen.getByText('median, p90 17 days, 37 fixed')).toBeInTheDocument()
    expect(screen.getByText('−29 hr').closest('p')).toHaveAttribute('data-tone', 'better')
  })
})

describe('Sparkline', () => {
  it('labels both ends with date and value, and reads as one sentence', () => {
    render(
      <StatViz
        result={{
          shape: 'scalar',
          value: 56,
          previous: 41,
          series: [
            { t: '2026-09-24', v: 43 },
            { t: '2026-10-08', v: 50 },
            { t: '2026-10-23', v: 56 },
          ],
        }}
      />
    )
    const spark = screen.getByTestId('sparkline')
    expect(within(spark).getByText('43')).toBeInTheDocument()
    expect(within(spark).getByText('Sep 24')).toBeInTheDocument()
    expect(within(spark).getByText('Oct 23')).toBeInTheDocument()
    expect(spark).toHaveTextContent('Trend from 43 on Sep 24 to 56 on Oct 23')
    // The change names its base.
    expect(screen.getByText('vs 41 previous period')).toBeInTheDocument()
  })

  it('draws nothing with fewer than two points', () => {
    render(<StatViz result={{ shape: 'scalar', value: 5, series: [{ t: '2026-10-01', v: 5 }] }} />)
    expect(screen.queryByTestId('sparkline')).toBeNull()
  })
})

describe('ProgressViz', () => {
  it('is a meter against the target, with icon and words', () => {
    render(
      <ProgressViz
        result={{
          shape: 'ratio',
          num: 86,
          den: 100,
          value_pct: 86,
          previous_pct: 83,
          target: { op: '>=', value: 95, warn: 85 },
        }}
      />
    )
    const meter = screen.getByRole('meter')
    expect(meter).toHaveAttribute('aria-valuenow', '86')
    expect(screen.getByText('close to target')).toBeInTheDocument()
    expect(screen.getByText('+3').closest('p')).toHaveAttribute('data-tone', 'better')
  })
})

const SEVERITY: CategoryResult = {
  shape: 'category',
  ordinal: true,
  total: 104,
  rows: [
    { key: 'critical', label: 'Critical', value: 22 },
    { key: 'high', label: 'High', value: 50 },
    { key: 'medium', label: 'Medium', value: 24 },
    { key: 'low', label: 'Low', value: 8 },
  ],
}

describe('BarViz', () => {
  it('names the figure by its largest rows', () => {
    render(<BarViz result={SEVERITY} />)
    expect(screen.getByRole('figure')).toHaveAccessibleName(
      'Largest: High 50, Medium 24, Critical 22'
    )
  })

  it('keeps ordinal order, prints values and links each bar to its list', () => {
    render(<BarViz result={SEVERITY} drill={({ key }) => `/findings?state=open&severity=${key}`} />)
    const links = screen.getAllByRole('link')
    expect(links.map((l) => l.getAttribute('aria-label'))).toEqual([
      'Critical: 22',
      'High: 50',
      'Medium: 24',
      'Low: 8',
    ])
    expect(links[0]).toHaveAttribute('href', '/findings?state=open&severity=critical')
  })

  it('folds keys past eight into Other unless ordinal', () => {
    const rows = Array.from({ length: 11 }, (_, i) => ({ key: `s${i}`, value: 11 - i }))
    const folded = barRows({ shape: 'category', rows, total: 66 }, 'Other')
    expect(folded).toHaveLength(8)
    expect(folded[7]).toMatchObject({ key: 'other', value: 4 + 3 + 2 + 1 })
    expect(barRows({ shape: 'category', rows, total: 66, ordinal: true }, 'Other')).toHaveLength(11)
  })

  it('has a table view with the total', () => {
    render(<BarViz result={SEVERITY} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show table' }))
    const table = screen.getByRole('table')
    expect(within(table).getByText('Total')).toBeInTheDocument()
    expect(within(table).getByText('104')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show chart' })).toBeInTheDocument()
  })

  it('stacked shows shares in the legend', () => {
    render(<BarViz result={SEVERITY} stacked />)
    expect(screen.getByText('(48%)')).toBeInTheDocument()
  })
})

const FLOW: TimeSeriesResult = {
  shape: 'time_series',
  bucket: 'week',
  kind: 'flow',
  series: [
    {
      key: 'opened',
      label: 'Opened',
      points: [
        { t: '2026-10-05', v: 10 },
        { t: '2026-10-12', v: 4 },
      ],
    },
    {
      key: 'fixed',
      label: 'Fixed',
      points: [
        { t: '2026-10-05', v: 12 },
        { t: '2026-10-12', v: 9 },
      ],
    },
  ],
}

describe('series visualizations', () => {
  it('toRows keeps missing points absent and can negate a series', () => {
    const rows = toRows(
      { ...FLOW, series: [FLOW.series[0], { key: 'fixed', points: [{ t: '2026-10-12', v: 9 }] }] },
      { fixed: -1 }
    )
    expect(rows[0]).toEqual({ t: '2026-10-05', opened: 10 })
    expect(rows[1]).toEqual({ t: '2026-10-12', opened: 4, fixed: -9 })
  })

  it('diverging bars state the net in words', () => {
    expect(netOf(FLOW)).toBe(-7)
    render(<DivergingViz result={FLOW} />)
    expect(screen.getByText('Fixing faster than finding: 7 fewer open')).toBeInTheDocument()
  })

  it('every chart is a figure named by a one-line summary (first and last bucket, latest values)', () => {
    render(<ColumnViz result={FLOW} />)
    const fig = screen.getByRole('figure')
    expect(fig).toHaveAccessibleName(/^Oct 5 to Oct 12\. Latest: /)
    expect(screen.getByTestId('chart-summary')).toHaveTextContent('Latest:')
    // The table twin replaces the figure.
    fireEvent.click(screen.getByRole('button', { name: 'Show table' }))
    expect(screen.queryByRole('figure')).toBeNull()
    expect(screen.getByRole('table')).toBeInTheDocument()
  })

  it('diverging bars name the net and the range', () => {
    render(<DivergingViz result={FLOW} />)
    expect(screen.getByRole('figure')).toHaveAccessibleName(
      /^Fixing faster than finding: 7 fewer open\. Oct 5 to Oct 12/
    )
  })

  it('columns have a table view with every point and drill links', () => {
    render(<ColumnViz result={FLOW} drill={({ series, t }) => `/findings?${series}_on=${t}`} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show table' }))
    const table = screen.getByRole('table')
    expect(within(table).getByText('Oct 5')).toBeInTheDocument()
    expect(within(table).getByRole('link', { name: '12' })).toHaveAttribute(
      'href',
      '/findings?fixed_on=2026-10-05'
    )
  })
})

describe('grid visualizations', () => {
  it('heatmap prints every value and shades on the ramp', () => {
    expect(heatStep(0, 10)).toBe(-1)
    expect(heatStep(10, 10)).toBe(4)
    render(
      <HeatmapViz
        result={{
          shape: 'matrix',
          rows: [{ key: 'critical', label: 'Critical' }],
          cols: [
            { key: '0-30', label: '0-30' },
            { key: '90+', label: '90+' },
          ],
          cells: [[9, 0]],
        }}
        drill={({ series, key }) => `/findings?severity=${series}&age_band=${key}`}
      />
    )
    expect(screen.getByRole('link', { name: 'Critical, 0-30: 9' })).toHaveAttribute(
      'href',
      '/findings?severity=critical&age_band=0-30'
    )
    expect(screen.getByText('0')).toBeInTheDocument()
    // Scale legend, the peak as the figure's name, a severity dot on the row.
    expect(screen.getByText('Fewer')).toBeInTheDocument()
    expect(screen.getByText('max 9')).toBeInTheDocument()
    expect(screen.getByRole('figure')).toHaveAccessibleName('Highest: Critical, 0-30: 9')
    expect(document.querySelector('.bg-sev-critical')).not.toBeNull()
  })

  it('stages show not measured as grey with the reason, never as good', () => {
    render(
      <LoopViz
        result={{
          shape: 'stages',
          stages: [
            { key: 'scope', label: 'Scope', value: 312, state: 'good', drill: '/scoping' },
            {
              key: 'validate',
              label: 'Validate',
              value: null,
              unit: 'percent',
              state: 'unmeasured',
            },
          ],
        }}
      />
    )
    expect(screen.getByRole('link', { name: /Scope/ })).toHaveAttribute('href', '/scoping')
    const validate = screen.getByText('Validate').closest('li')!
    expect(validate).toHaveAttribute('data-state', 'unmeasured')
    expect(within(validate).getByText('Not measured')).toBeInTheDocument()
    expect(within(validate).getByText('—')).toBeInTheDocument()
  })

  it('items link rows and the full list', () => {
    render(
      <ItemsViz
        result={{
          shape: 'items',
          total: 20,
          rows: [
            {
              id: 'f1',
              title: 'RCE in edge gateway',
              priority: 'P0',
              kev: true,
              href: '/findings/f1',
            },
          ],
        }}
        viewAllHref="/findings?state=open"
      />
    )
    expect(screen.getByRole('link', { name: /RCE in edge gateway/ })).toHaveAttribute(
      'href',
      '/findings/f1'
    )
    expect(screen.getByText('KEV')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View all 20' })).toHaveAttribute(
      'href',
      '/findings?state=open'
    )
  })

  it('a finding stored without a title shows a named placeholder, still linked', () => {
    render(
      <ItemsViz
        result={{
          shape: 'items',
          total: 2,
          rows: [
            { id: 'f1', title: '', href: '/findings/f1' },
            { id: 'f2', title: '   ', href: '/findings/f2' },
          ],
        }}
      />
    )
    const links = screen.getAllByRole('link', { name: /Untitled finding/ })
    expect(links.map((l) => l.getAttribute('href'))).toEqual(['/findings/f1', '/findings/f2'])
  })
})

describe('ItemsViz View all', () => {
  const row = { id: 'f1', title: 'A finding', href: '/findings/f1', severity: 'high' }
  it('shows no number unless the server sent a list total (never the row count)', () => {
    render(
      <ItemsViz
        result={{ shape: 'items', rows: [row, { ...row, id: 'f2' }] }}
        viewAllHref="/findings"
      />
    )
    const link = screen.getByRole('link', { name: 'View all' })
    expect(link).toHaveAttribute('href', '/findings')
  })
  it('shows the real total when sent', () => {
    render(
      <ItemsViz result={{ shape: 'items', rows: [row], total: 340 }} viewAllHref="/findings" />
    )
    expect(screen.getByRole('link', { name: 'View all 340' })).toBeInTheDocument()
  })
  it('marks an overdue row with the word Overdue and shows severity', () => {
    render(
      <ItemsViz
        result={{
          shape: 'items',
          rows: [{ ...row, due_at: new Date(Date.now() - 3 * 86_400_000).toISOString() }],
        }}
      />
    )
    expect(screen.getByText(/^Overdue/)).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
  })
})

describe('ItemsViz row grid', () => {
  it('a row with no severity and no due date keeps the dot slot and a due column', () => {
    render(
      <ItemsViz
        result={{
          shape: 'items',
          rows: [
            {
              id: 'a',
              title: 'Full',
              priority: 'P1',
              severity: 'high',
              due_at: '2999-01-01T00:00:00Z',
              href: '/findings/a',
            },
            {
              id: 'b',
              title: 'Bare',
              priority: 'P1',
              severity: 'none',
              due_at: null,
              href: '/findings/b',
            },
            {
              id: 'c',
              title: 'Odd',
              priority: 'P1',
              severity: 'weird',
              due_at: null,
              href: '/findings/c',
            },
          ],
        }}
      />
    )
    expect(screen.getAllByTestId('items-severity-dot')).toHaveLength(3)
    expect(screen.getAllByText('No due date')).toHaveLength(2)
    const odd = screen.getByRole('link', { name: /Odd/ })
    expect(within(odd).getByText('Unknown')).toBeInTheDocument()
    const bare = screen.getByRole('link', { name: /Bare/ })
    expect(within(bare).getByText('Info')).toBeInTheDocument()
  })
})
