import { describe, it, expect } from 'vitest'
import { dashboardDataKey, dashboardRefreshPath } from '../widget-data'

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
