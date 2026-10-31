import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MetricStrip, phoneSpan, smColumns } from '../metric-strip'

describe('MetricStrip', () => {
  it('renders each label and a locale-formatted value', () => {
    render(
      <MetricStrip
        items={[
          { key: 'total', label: 'All findings', value: 12773 },
          { key: 'ratio', label: 'SLA', value: '98%' },
        ]}
      />
    )
    expect(screen.getByText('All findings')).toBeInTheDocument()
    expect(screen.getByText((12773).toLocaleString())).toBeInTheDocument()
    expect(screen.getByText('98%')).toBeInTheDocument()
  })

  it('colours a danger metric only while it is positive — a zero stays neutral', () => {
    render(
      <MetricStrip
        items={[
          { key: 'a', label: 'Overdue', value: 3, tone: 'danger' },
          { key: 'b', label: 'In KEV', value: 0, tone: 'danger' },
        ]}
      />
    )
    expect(screen.getByText('3')).toHaveClass('text-destructive')
    expect(screen.getByText('0')).not.toHaveClass('text-destructive')
  })

  it('makes clickable metrics toggle buttons that report their pressed state', () => {
    const onClick = vi.fn()
    render(
      <MetricStrip
        items={[
          { key: 'crit', label: 'Critical', value: 22, onClick, active: true },
          { key: 'total', label: 'Total', value: 93 },
        ]}
      />
    )
    const btn = screen.getByRole('button', { name: /critical/i })
    expect(btn).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(btn)
    expect(onClick).toHaveBeenCalledTimes(1)
    // Non-clickable metrics are not buttons.
    expect(screen.queryByRole('button', { name: /total/i })).not.toBeInTheDocument()
  })

  it('balances the tablet grid so no metric is left alone on a row', () => {
    const cols = [1, 2, 3, 4, 5, 6, 7, 8].map(smColumns)
    expect(cols).toEqual([1, 2, 3, 4, 3, 3, 4, 4])
    for (let n = 2; n <= 8; n++) expect(n % smColumns(n)).not.toBe(1)
  })

  it('fills every phone row in at most two rows, never a lone tile', () => {
    const rows = (n: number) => Array.from({ length: n }, (_, i) => phoneSpan(n, i))
    expect(rows(1)).toEqual([6])
    expect(rows(2)).toEqual([3, 3])
    expect(rows(3)).toEqual([2, 2, 2])
    expect(rows(4)).toEqual([3, 3, 3, 3])
    expect(rows(5)).toEqual([2, 2, 2, 3, 3])
    for (let n = 1; n <= 5; n++) {
      const total = rows(n).reduce((a, b) => a + b, 0)
      expect(total % 6, `${n} tiles fill whole rows`).toBe(0)
      expect(total / 6, `${n} tiles take at most two rows`).toBeLessThanOrEqual(2)
    }
  })

  it('never puts a detailed strip in thirds on a phone: halves, the first tile full when odd', () => {
    const rows = (n: number) => Array.from({ length: n }, (_, i) => phoneSpan(n, i, true))
    expect(rows(1)).toEqual([6])
    expect(rows(2)).toEqual([3, 3])
    expect(rows(3)).toEqual([6, 3, 3])
    expect(rows(4)).toEqual([3, 3, 3, 3])
    expect(rows(5)).toEqual([6, 3, 3, 3, 3])
    for (let n = 1; n <= 5; n++) {
      expect(rows(n).reduce((a, b) => a + b, 0) % 6, `${n} tiles fill whole rows`).toBe(0)
    }
  })

  it('lays a strip with detail lines out in halves and keeps its captions on a phone', () => {
    const { container } = render(
      <MetricStrip
        items={[
          { key: 'a', label: 'Fleet health', value: 0, hint: 'of 1 can take jobs', detail: 'x' },
          {
            key: 'b',
            label: 'Needs attention',
            value: 1,
            detail: 'storage full',
            onClick: vi.fn(),
          },
          { key: 'c', label: 'Updates', value: 0, detail: 'all on the latest', onClick: vi.fn() },
        ]}
      />
    )
    const tiles = Array.from(container.querySelectorAll('[data-slot="metric-tile"]'))
    expect(tiles.map((t) => t.className.match(/(?:^| )(col-span-\d)/)?.[1])).toEqual([
      'col-span-6',
      'col-span-3',
      'col-span-3',
    ])
    expect(screen.getByText('of 1 can take jobs')).not.toHaveClass('hidden')
  })

  it('starts every tile at the top, a toggle button too', () => {
    const { container } = render(
      <MetricStrip
        items={[
          { key: 'a', label: 'Total', value: 3 },
          { key: 'b', label: 'Open', value: 1, onClick: vi.fn() },
        ]}
      />
    )
    for (const tile of Array.from(container.querySelectorAll('[data-slot="metric-tile"]'))) {
      expect(tile).toHaveClass('flex', 'flex-col', 'justify-start')
    }
  })

  it('keeps a compact strip in thirds with two label lines, the caption in the tooltip', () => {
    const { container } = render(
      <MetricStrip
        items={[
          { key: 'a', label: 'Zones', value: 0, hint: 'covered' },
          { key: 'b', label: 'Inventory addresses', value: 0 },
          { key: 'c', label: 'Inside a zone', value: 0 },
        ]}
      />
    )
    const tiles = Array.from(container.querySelectorAll('[data-slot="metric-tile"]'))
    for (const tile of tiles) {
      expect(tile).toHaveClass('col-span-2')
      expect(tile.querySelector('[data-slot="metric-label"]')).toHaveClass('min-h-8')
    }
    expect(screen.getByText('covered')).toHaveClass('hidden')
  })

  it('shows skeletons instead of values while loading', () => {
    render(<MetricStrip loading items={[{ key: 't', label: 'Total', value: 93 }]} />)
    expect(screen.getByText('Total')).toBeInTheDocument()
    expect(screen.queryByText('93')).not.toBeInTheDocument()
  })

  it('keeps the tile height while loading: value line and detail line hold their place', () => {
    const { container } = render(
      <MetricStrip
        loading
        items={[
          { key: 't', label: 'Total', value: 93, detail: '4 new this week' },
          { key: 'u', label: 'Other', value: 2 },
        ]}
      />
    )
    const values = container.querySelectorAll('[data-slot="metric-value"] > span')
    // The skeleton sits in a box of the value's line height (28px, 32px from sm).
    expect(values[0]).toHaveClass('h-7', 'sm:h-8')
    // A tile with a detail reserves its line; one without reserves nothing.
    const details = container.querySelectorAll('[data-slot="metric-detail"]')
    expect(details).toHaveLength(1)
    expect(details[0]).toHaveClass('h-4')
    expect(screen.queryByText('4 new this week')).not.toBeInTheDocument()
  })
})

describe('MetricStrip warning tone and detail', () => {
  it('colours a warning metric only while positive, and shows its detail', () => {
    render(
      <MetricStrip
        items={[
          { key: 'a', label: 'Needs attention', value: 3, tone: 'warning', detail: 'backlog, key' },
          { key: 'b', label: 'Updates', value: 0, tone: 'warning' },
        ]}
      />
    )
    expect(screen.getByText('3')).toHaveClass('text-warning')
    expect(screen.getByText('0')).not.toHaveClass('text-warning')
    expect(screen.getByText('backlog, key')).toBeInTheDocument()
  })
})
