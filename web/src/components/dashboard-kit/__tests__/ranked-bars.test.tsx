import axe from 'axe-core'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { RankedBars, rankMoves, rankRows, splitRanked, type RankedBarRow } from '../ranked-bars'

const rows: RankedBarRow[] = [
  { key: 'b', label: 'beta', value: 12, href: '/findings/imports?tool=beta' },
  { key: 'a', label: 'alpha', value: 59, href: '/findings/imports?tool=alpha' },
  { key: 'z1', label: 'zero-one', value: 0 },
  { key: 'z2', label: 'zero-two', value: 0, health: 'stale', note: 'Stale, last 3 days ago' },
  { key: 'c', label: 'gamma', value: 3 },
  { key: 'd', label: 'delta', value: 3 },
]

const zeroLabel = (n: number) => `+${n} with nothing`
const order = () =>
  [...document.querySelectorAll('li[data-key]')].map((li) => li.getAttribute('data-key'))

function setMotion(reduce: boolean) {
  window.matchMedia = vi.fn(
    (q: string) =>
      ({
        matches: reduce && q.includes('reduce'),
        media: q,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        onchange: null,
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList
  ) as unknown as typeof window.matchMedia
}

const realMatchMedia = window.matchMedia
afterEach(() => {
  vi.restoreAllMocks()
  window.matchMedia = realMatchMedia
})

describe('rankRows / splitRanked / rankMoves', () => {
  it('orders by value, then label, stably', () => {
    expect(rankRows(rows).map((r) => r.key)).toEqual(['a', 'b', 'd', 'c', 'z1', 'z2'])
  })

  it('folds healthy zeros only; an unhealthy zero stays in view', () => {
    const { shown, rest, zeros } = splitRanked(rankRows(rows), 3)
    expect(shown.map((r) => r.key)).toEqual(['a', 'b', 'd'])
    expect(rest.map((r) => r.key)).toEqual(['c', 'z2'])
    expect(zeros.map((r) => r.key)).toEqual(['z1'])
  })

  it('counts places climbed and fallen', () => {
    expect(rankMoves(['a', 'b', 'c'], ['c', 'a', 'b'])).toEqual({ c: 2, a: -1, b: -1 })
    expect(rankMoves(['a'], ['a', 'new'])).toEqual({})
  })
})

describe('RankedBars', () => {
  it('draws the largest first, each row a link at least 44 px tall, bars scaled to the max', () => {
    render(<RankedBars rows={rows} limit={6} label="Sources" zeroLabel={zeroLabel} />)
    expect(order()).toEqual(['a', 'b', 'd', 'c', 'z2'])
    const top = screen.getByRole('link', { name: 'alpha 59' })
    expect(top).toHaveAttribute('href', '/findings/imports?tool=alpha')
    expect(top.className).toContain('min-h-11')
    const bars = screen.getAllByTestId('ranked-bar')
    expect(bars[0].style.width).toBe('100%')
    expect(parseFloat(bars[1].style.width)).toBeCloseTo((100 * 12) / 59, 1)
    // No safe link: plain text in the same box, still focusable for its tooltip.
    expect(screen.queryByRole('link', { name: 'gamma 3' })).not.toBeInTheDocument()
    expect(screen.getByText('Stale, last 3 days ago')).toBeInTheDocument()
    // The health words wrap under the name; they are never cut off.
    expect(screen.getByText('Stale, last 3 days ago').className).not.toContain('truncate')
  })

  it('folds healthy zeros into one line that expands on tap', async () => {
    const user = userEvent.setup()
    render(<RankedBars rows={rows} limit={6} label="Sources" zeroLabel={zeroLabel} />)
    const fold = screen.getByTestId('ranked-zeros')
    expect(fold).toHaveTextContent('+1 with nothing')
    expect(fold).toHaveAttribute('aria-expanded', 'false')
    await user.click(fold)
    expect(order()).toContain('z1')
    expect(fold).toHaveAttribute('aria-expanded', 'true')
  })

  it('shows the first rows and "Show all" for the rest', async () => {
    const user = userEvent.setup()
    render(<RankedBars rows={rows} limit={2} label="Sources" zeroLabel={zeroLabel} />)
    expect(order()).toEqual(['a', 'b'])
    await user.click(screen.getByRole('button', { name: 'Show all 5' }))
    expect(order()).toEqual(['a', 'b', 'd', 'c', 'z2'])
  })

  it('marks a rank change for one cycle and announces the biggest climber once', () => {
    setMotion(false)
    const animate = vi.fn()
    HTMLElement.prototype.animate = animate as unknown as HTMLElement['animate']
    const { rerender } = render(
      <RankedBars rows={rows} limit={6} label="Sources" zeroLabel={zeroLabel} />
    )
    expect(screen.queryAllByTestId('rank-move')).toHaveLength(0)
    const next = rows.map((r) => (r.key === 'c' ? { ...r, value: 100 } : r))
    rerender(<RankedBars rows={next} limit={6} label="Sources" zeroLabel={zeroLabel} />)
    expect(order()[0]).toBe('c')
    const marks = screen.getAllByTestId('rank-move')
    expect(marks[0]).toHaveTextContent('3')
    expect(screen.getByTestId('ranked-announce')).toHaveTextContent('gamma moved to number 1')
  })

  it('does not animate under reduced motion but still marks the change', () => {
    setMotion(true)
    const animate = vi.fn()
    HTMLElement.prototype.animate = animate as unknown as HTMLElement['animate']
    const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect')
    let y = 0
    rect.mockImplementation(() => ({ top: (y += 50), left: 0, width: 10, height: 44 }) as DOMRect)
    const { rerender } = render(
      <RankedBars rows={rows} limit={6} label="Sources" zeroLabel={zeroLabel} />
    )
    rerender(
      <RankedBars
        rows={rows.map((r) => (r.key === 'c' ? { ...r, value: 100 } : r))}
        limit={6}
        label="Sources"
        zeroLabel={zeroLabel}
      />
    )
    expect(animate).not.toHaveBeenCalled()
    expect(screen.getAllByTestId('rank-move').length).toBeGreaterThan(0)
  })

  it('animates a move when motion is allowed', () => {
    setMotion(false)
    const animate = vi.fn()
    HTMLElement.prototype.animate = animate as unknown as HTMLElement['animate']
    const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect')
    let y = 0
    rect.mockImplementation(() => ({ top: (y += 50), left: 0, width: 10, height: 44 }) as DOMRect)
    const { rerender } = render(
      <RankedBars rows={rows} limit={6} label="Sources" zeroLabel={zeroLabel} />
    )
    rerender(
      <RankedBars
        rows={rows.map((r) => (r.key === 'c' ? { ...r, value: 100 } : r))}
        limit={6}
        label="Sources"
        zeroLabel={zeroLabel}
      />
    )
    expect(animate).toHaveBeenCalled()
    const [, opts] = animate.mock.calls[0]
    expect(opts.duration).toBeLessThanOrEqual(250)
  })

  it('re-sorts without rank marks when the viewer switches what is ranked', () => {
    setMotion(true)
    const { rerender } = render(
      <RankedBars rows={rows} limit={6} label="Sources" zeroLabel={zeroLabel} resetKey="findings" />
    )
    rerender(
      <RankedBars
        rows={rows.map((r) => (r.key === 'c' ? { ...r, value: 100 } : r))}
        limit={6}
        label="Sources"
        zeroLabel={zeroLabel}
        resetKey="assets"
      />
    )
    expect(order()[0]).toBe('c')
    expect(screen.queryAllByTestId('rank-move')).toHaveLength(0)
    expect(screen.getByTestId('ranked-announce')).toHaveTextContent('')
  })

  it('names a row by its own text, so the name holds what is visible (label in name)', async () => {
    const { container } = render(
      <RankedBars
        rows={[
          {
            key: 'n',
            label: 'nuclei',
            chip: 'Sensor',
            value: 26,
            display: '26',
            unit: '26 findings',
            href: '/findings/imports?tool=nuclei',
          },
        ]}
        limit={6}
        label="Sources"
        zeroLabel={zeroLabel}
      />
    )
    expect(screen.getByRole('link', { name: 'nuclei Sensor 26 findings' })).toBeInTheDocument()
    const res = await axe.run(container, { runOnly: ['label-content-name-mismatch'] })
    expect(res.violations).toEqual([])
  })
})
