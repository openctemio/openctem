import { describe, it, expect } from 'vitest'
import {
  dashboardDataKey,
  dashboardRefreshInterval,
  dashboardRefreshPath,
  type DashboardData,
} from '../widget-data'

const NOW = Date.parse('2026-10-23T10:00:00Z')
const snap = (extra: Partial<DashboardData>) =>
  ({ facts_built_at: '2026-10-23T09:00:00Z', ...extra }) as DashboardData

describe('dashboardRefreshInterval', () => {
  it('waits for the next scheduled refresh plus 5s', () => {
    const next = new Date(NOW + 10 * 60_000).toISOString()
    expect(dashboardRefreshInterval(snap({ next_refresh_at: next }), NOW)).toBe(10 * 60_000 + 5_000)
  })
  it('never polls faster than 30s, even when the refresh is overdue', () => {
    const next = new Date(NOW - 60_000).toISOString()
    expect(dashboardRefreshInterval(snap({ next_refresh_at: next }), NOW)).toBe(30_000)
  })
  it('polls every 15s while the first build runs', () => {
    expect(dashboardRefreshInterval(snap({ facts_built_at: null }), NOW)).toBe(15_000)
  })
  it('does not poll a manual dashboard or before data arrives', () => {
    expect(dashboardRefreshInterval(snap({}), NOW)).toBe(0)
    expect(dashboardRefreshInterval(undefined, NOW)).toBe(0)
  })
})

describe('widget data keys', () => {
  it('personal and organization dashboards read their own routes', () => {
    expect(dashboardDataKey('personal', 'd1')).toBe('/api/v1/me/dashboards/d1/data')
    expect(dashboardDataKey('organization', 'd1')).toBe('/api/v1/organization/dashboards/d1/data')
  })

  it("Refresh now posts to the dashboard kind's own route", () => {
    expect(dashboardRefreshPath('personal', 'd1')).toBe('/api/v1/me/dashboards/d1/refresh')
    expect(dashboardRefreshPath('organization', 'd1')).toBe(
      '/api/v1/organization/dashboards/d1/refresh'
    )
  })
})
