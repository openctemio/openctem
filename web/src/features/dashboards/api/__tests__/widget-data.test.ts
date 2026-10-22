import { describe, it, expect } from 'vitest'
import { dashboardDataKey } from '../widget-data'

describe('widget data keys', () => {
  it('personal and organization dashboards read their own routes', () => {
    expect(dashboardDataKey('personal', 'd1')).toBe('/api/v1/me/dashboards/d1/data')
    expect(dashboardDataKey('organization', 'd1')).toBe('/api/v1/organization/dashboards/d1/data')
  })
})
