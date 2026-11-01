import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ProgramMetrics } from '../../hooks/use-ctem-dashboard'

let hookResult: {
  data?: ProgramMetrics
  error?: unknown
  isLoading: boolean
  mutate: () => void
}

vi.mock('../../hooks/use-ctem-dashboard', () => ({
  useProgramMetrics: () => hookResult,
}))

import { ProgramMetricsSection } from '../program-metrics-section'

// The API's JSON carries null for "not measurable"; the generated type models
// it as an optional number, so cast the literal the server really sends.
const empty = {
  period_days: 90,
  mttd_internet_facing: { mean_hours: null, median_hours: null, sample_size: 0, unmeasured: 0 },
  mttr_validated: { mean_hours: null, median_hours: null, sample_size: 0, unmeasured: 0 },
  owner_acceptance: { rate_pct: null, accepted: 0, missed: 0, pending: 0, excluded: 0 },
  mttv: { mean_hours: null, median_hours: null, sample_size: 0, unmeasured: 0 },
  time_to_owner_internet_facing: {
    mean_hours: null,
    median_hours: null,
    sample_size: 0,
    unmeasured: 0,
  },
  cycle_completion: {
    due: 0,
    closed_on_time: 0,
    closed_late: 0,
    open: 0,
    rate_pct: null,
    mean_charter_completion_pct: null,
  },
  control_coverage: [
    { control: 'edr', total: 0, covered: 0, lacking: 0, unknown: 0, gap_pct: null },
    { control: 'mfa', total: 0, covered: 0, lacking: 0, unknown: 0, gap_pct: null },
    { control: 'logging', total: 0, covered: 0, lacking: 0, unknown: 0, gap_pct: null },
  ],
} as unknown as ProgramMetrics

// The same numbers the API DB fixtures assert.
const measured = {
  period_days: 90,
  mttd_internet_facing: { mean_hours: 16.5, median_hours: 9, sample_size: 4, unmeasured: 1 },
  mttr_validated: { mean_hours: 36, median_hours: 24, sample_size: 3, unmeasured: 0 },
  owner_acceptance: { rate_pct: 75, accepted: 3, missed: 1, pending: 1, excluded: 4 },
  mttv: { mean_hours: 10, median_hours: 6, sample_size: 3, unmeasured: 1 },
  time_to_owner_internet_facing: { mean_hours: 14, median_hours: 2, sample_size: 3, unmeasured: 1 },
  cycle_completion: {
    due: 4,
    closed_on_time: 2,
    closed_late: 1,
    open: 1,
    rate_pct: 50,
    mean_charter_completion_pct: 60,
  },
  control_coverage: [
    { control: 'edr', total: 5, covered: 2, lacking: 1, unknown: 2, gap_pct: 60 },
    { control: 'mfa', total: 1, covered: 0, lacking: 1, unknown: 0, gap_pct: 100 },
    { control: 'logging', total: 0, covered: 0, lacking: 0, unknown: 0, gap_pct: null },
  ],
} as unknown as ProgramMetrics

function valueOf(title: string): HTMLElement {
  const row = screen.getByText(title).closest('[data-slot="metric-row"]') as HTMLElement
  return row.querySelector('[data-slot="metric-row-value"]') as HTMLElement
}

describe('ProgramMetricsSection', () => {
  beforeEach(() => {
    hookResult = { isLoading: false, mutate: vi.fn() }
  })

  it('shows "Not measured" for every metric when there is no data (never 0 or 100%)', () => {
    hookResult.data = empty
    render(<ProgramMetricsSection tenantId="t1" days={90} />)

    for (const title of [
      'Time to detect internet-facing assets',
      'Time to remediate validated exposures',
      'Owner acceptance rate',
      'Time to break attack paths',
      'Time to validate priority exposures',
      'Time to assign an owner',
      'Cycles completed on time',
      'Critical hosts without EDR',
      'Critical accounts without MFA',
      'Critical storage without logging',
    ]) {
      const v = valueOf(title)
      expect(v.textContent).toBe('Not measured')
      expect(v.className).toContain('text-muted-foreground')
      expect(v.className).not.toContain('text-destructive')
    }
    expect(screen.queryByText(/^0%$/)).toBeNull()
    expect(screen.queryByText(/^100%$/)).toBeNull()
    expect(screen.getAllByText('No new internet-facing assets in this period')).toHaveLength(2)
    expect(screen.getByText('No validated exposures resolved in this period')).toBeTruthy()
    expect(screen.getByText('No assignments with an SLA in this period')).toBeTruthy()
    expect(screen.getByText('No P0 or P1 findings detected in this period')).toBeTruthy()
    expect(screen.getByText('No cycle was due in this period')).toBeTruthy()
    expect(screen.getAllByText('No critical assets of this kind')).toHaveLength(3)
  })

  it('renders measured values with their sample captions', () => {
    hookResult.data = measured
    render(<ProgramMetricsSection tenantId="t1" days={90} />)

    expect(valueOf('Time to detect internet-facing assets').textContent).toBe('16.5 h')
    expect(screen.getByText('Median 9 h, 4 assets (+1 not timed yet)')).toBeTruthy()
    expect(valueOf('Time to remediate validated exposures').textContent).toBe('36 h')
    expect(screen.getByText('Median 24 h, 3 findings')).toBeTruthy()
    expect(valueOf('Owner acceptance rate').textContent).toBe('75%')
    expect(screen.getByText('3 of 4 assignments in SLA, 1 pending')).toBeTruthy()
    expect(valueOf('Time to validate priority exposures').textContent).toBe('10 h')
    expect(screen.getByText('Median 6 h, 3 findings (+1 not timed yet)')).toBeTruthy()
    expect(valueOf('Time to assign an owner').textContent).toBe('14 h')
    expect(screen.getByText('Median 2 h, 3 assets (+1 not timed yet)')).toBeTruthy()
    expect(valueOf('Cycles completed on time').textContent).toBe('50%')
    expect(screen.getByText('2 of 4 cycles on time, 1 late, 1 open, criteria met 60%')).toBeTruthy()
    expect(valueOf('Critical hosts without EDR').textContent).toBe('60%')
    expect(screen.getByText('1 lacking, 2 not recorded, of 5 assets')).toBeTruthy()
    expect(valueOf('Critical accounts without MFA').textContent).toBe('100%')
    // No critical storage: not measured, never 0%.
    expect(valueOf('Critical storage without logging').textContent).toBe('Not measured')
    // Time-to-break is never computed, even when everything else is.
    expect(valueOf('Time to break attack paths').textContent).toBe('Not measured')
  })

  it('never colours a zero rate red', () => {
    hookResult.data = {
      ...measured,
      owner_acceptance: { rate_pct: 0, accepted: 0, missed: 2, pending: 0, excluded: 0 },
    } as unknown as ProgramMetrics
    render(<ProgramMetricsSection tenantId="t1" days={90} />)
    const v = valueOf('Owner acceptance rate')
    expect(v.textContent).toBe('0%')
    expect(v.className).not.toContain('text-destructive')
  })

  it('says why owner acceptance is not measured when every assignment is pending', () => {
    hookResult.data = {
      ...empty,
      owner_acceptance: { rate_pct: null, accepted: 0, missed: 0, pending: 2, excluded: 0 },
    } as unknown as ProgramMetrics
    render(<ProgramMetricsSection tenantId="t1" days={90} />)
    expect(valueOf('Owner acceptance rate').textContent).toBe('Not measured')
    expect(screen.getByText('2 assignments still inside the SLA window')).toBeTruthy()
  })

  it('exposes each definition behind a labelled info button', () => {
    hookResult.data = measured
    render(<ProgramMetricsSection tenantId="t1" days={90} />)
    expect(
      screen.getByRole('button', { name: 'How Owner acceptance rate is measured' })
    ).toBeTruthy()
    expect(screen.getAllByRole('button', { name: /is measured$/ })).toHaveLength(10)
  })

  it('says how many items are still untimed when nothing could be timed', () => {
    hookResult.data = {
      ...empty,
      time_to_owner_internet_facing: {
        mean_hours: null,
        median_hours: null,
        sample_size: 0,
        unmeasured: 2,
      },
    } as unknown as ProgramMetrics
    render(<ProgramMetricsSection tenantId="t1" days={90} />)
    expect(valueOf('Time to assign an owner').textContent).toBe('Not measured')
    expect(screen.getByText('2 assets still without an owner')).toBeTruthy()
  })

  it('shows an error state with retry instead of numbers when the request fails', () => {
    hookResult.error = new Error('boom')
    render(<ProgramMetricsSection tenantId="t1" days={90} />)
    expect(screen.getByText('Failed to load program metrics')).toBeTruthy()
    expect(screen.queryByText('Owner acceptance rate')).toBeNull()
  })
})
