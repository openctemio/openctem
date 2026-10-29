import { describe, expect, it } from 'vitest'
import userEvent from '@testing-library/user-event'
import { render, screen } from '@testing-library/react'
import { EpssSparkline, EpssTrendCard } from '../components/epss-trend'
import { epssChange, epssSeries } from '../lib/epss-trend'
import type { EpssPoint } from '../types/list'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const POINTS: EpssPoint[] = [
  { date: '2026-09-28', score: 0.1 },
  { date: '2026-10-12', score: 0.25 },
  { date: '2026-10-27', score: 0.4 },
]

describe('epss trend helpers', () => {
  it('turns scores into percent points and drops bad values', () => {
    expect(epssSeries([...POINTS, { date: '2026-10-28', score: Number.NaN }])).toEqual([
      { t: '2026-09-28', v: 10 },
      { t: '2026-10-12', v: 25 },
      { t: '2026-10-27', v: 40 },
    ])
    expect(epssSeries(undefined)).toEqual([])
  })

  it('reports the change in percentage points, none with fewer than two points', () => {
    expect(epssChange(POINTS)).toBe(30)
    expect(epssChange(POINTS.slice(0, 1))).toBeNull()
    expect(epssChange(undefined)).toBeNull()
  })
})

describe('EpssSparkline', () => {
  it('draws a line with a sentence for screen readers and no printed ends', () => {
    render(<EpssSparkline points={POINTS} />)
    const fig = screen.getByTestId('sparkline')
    expect(fig.querySelector('path')).not.toBeNull()
    expect(fig.querySelector('.sr-only')?.textContent).toMatch(/10%.*40%/)
    expect(fig.querySelectorAll('[aria-hidden] .font-medium')).toHaveLength(0)
  })

  it('draws nothing with fewer than two points', () => {
    const { container } = render(<EpssSparkline points={POINTS.slice(0, 1)} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('EpssTrendCard', () => {
  it('shows the chart with the change and a table view', async () => {
    render(<EpssTrendCard points={POINTS} />)
    expect(screen.getByText('Exploit prediction over 30 days')).toBeInTheDocument()
    expect(screen.getByText(/\+30.*in 30 days/)).toBeInTheDocument()
    expect(screen.getByTestId('chart-summary')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Show table' }))
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(screen.queryByTestId('epss-trend-empty')).toBeNull()
  })

  it('says why there is no trend when the API sends none', () => {
    render(<EpssTrendCard points={undefined} />)
    expect(screen.getByTestId('epss-trend-empty')).toBeInTheDocument()
    expect(screen.queryByText(/in 30 days$/)).toBeNull()
  })
})
