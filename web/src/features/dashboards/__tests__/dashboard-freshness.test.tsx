import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { DashboardData } from '../api/widget-data'
import { DashboardFreshness } from '../components/dashboard-freshness'

const data = (nextInMs: number): DashboardData => ({
  dashboard_id: 'd',
  scope: 'personal',
  restricted: false,
  facts_built_at: '2026-10-21T00:00:00Z',
  computed_at: new Date(Date.now() - 3_600_000).toISOString(),
  next_refresh_at: new Date(Date.now() + nextInMs).toISOString(),
  stale: false,
  widgets: [],
})

describe('DashboardFreshness next refresh', () => {
  it('shows the next refresh while it is ahead', () => {
    render(<DashboardFreshness kind="personal" data={data(3_600_000)} />)
    expect(screen.getByTestId('dashboard-freshness')).toHaveTextContent(/Next /)
    expect(screen.getByTestId('dashboard-freshness')).not.toHaveTextContent('Refresh due')
  })

  it('reads as due, never "Next … ago", once the scheduled time has passed', () => {
    render(<DashboardFreshness kind="personal" data={data(-21_000)} />)
    const line = screen.getByTestId('dashboard-freshness')
    expect(line).toHaveTextContent('Refresh due')
    expect(line).not.toHaveTextContent(/Next .*ago/)
  })
})
