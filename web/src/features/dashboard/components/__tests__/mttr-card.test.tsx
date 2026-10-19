import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MTTRCard } from '../mttr-card'
import { formatHours } from '../../lib/format-hours'

const useMttrAnalytics = vi.hoisted(() => vi.fn())
vi.mock('../../hooks/use-ctem-dashboard', () => ({ useMttrAnalytics }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/components/charts', () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>
  const Null = () => null
  return {
    BarChart: Pass,
    ResponsiveContainer: Pass,
    Bar: Null,
    XAxis: Null,
    YAxis: Null,
    Tooltip: Null,
    CartesianGrid: Null,
  }
})

// research/188 A-005: the Classic card averaged the per-severity means
// ((240 h + 192 h) / 2 = 9d) while the Executive page showed the API's
// overall 187.2 h (7.8d). Both now read overall_hours and format it alike.
describe('MTTRCard', () => {
  it('shows the API overall figure, the same as the Executive page', () => {
    useMttrAnalytics.mockReturnValue({
      data: {
        by_severity: { critical: 240, high: 192 },
        by_priority_class: {},
        overall_hours: 187.2,
        overall_median_hours: 150,
        overall_p90_hours: 300,
        sample_size: 5,
      },
    })
    render(<MTTRCard />)
    expect(screen.getByText(formatHours(187.2))).toBeInTheDocument()
    expect(screen.getByText('7.8d')).toBeInTheDocument()
    expect(screen.queryByText('9.0d')).toBeNull()
  })

  it('shows "—" for a severity with nothing fixed, never 0m', () => {
    useMttrAnalytics.mockReturnValue({
      data: {
        by_severity: {},
        by_priority_class: {},
        overall_hours: null,
        overall_median_hours: null,
        overall_p90_hours: null,
        sample_size: 0,
      },
    })
    render(<MTTRCard />)
    expect(screen.queryByText('0m')).toBeNull()
    expect(screen.getAllByText('—')).toHaveLength(3)
  })
})
