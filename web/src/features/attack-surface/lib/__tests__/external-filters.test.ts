import { describe, expect, it } from 'vitest'
import { DEFAULT_RISK_LEVELS } from '@/features/shared/types'
import { externalSurfaceFilters, riskRange } from '../external-filters'

describe('externalSurfaceFilters', () => {
  it('always scopes to internet-facing assets, never to the unused "external" scope', () => {
    const f = externalSurfaceFilters({}, DEFAULT_RISK_LEVELS)
    expect(f).toEqual({ exposures: ['public'], attribution: ['approved'] })
    expect(f.scopes).toBeUndefined()
  })

  it('maps search, type, risk band and findings to server filters', () => {
    expect(
      externalSurfaceFilters(
        { search: 'api', type: 'subdomain', risk: 'high', withFindings: true },
        DEFAULT_RISK_LEVELS
      )
    ).toEqual({
      exposures: ['public'],
      attribution: ['approved'],
      search: 'api',
      types: ['subdomain'],
      minRiskScore: 60,
      maxRiskScore: 79,
      hasFindings: true,
    })
  })

  it('ignores the "all" sentinels', () => {
    expect(externalSurfaceFilters({ type: 'all', risk: 'all' }, DEFAULT_RISK_LEVELS)).toEqual({
      exposures: ['public'],
      attribution: ['approved'],
    })
  })
})

describe('riskRange', () => {
  it('follows the tenant thresholds without gaps or overlaps', () => {
    const t = { critical_min: 90, high_min: 70, medium_min: 40, low_min: 10 }
    expect(riskRange('critical', t)).toEqual({ minRiskScore: 90 })
    expect(riskRange('high', t)).toEqual({ minRiskScore: 70, maxRiskScore: 89 })
    expect(riskRange('medium', t)).toEqual({ minRiskScore: 40, maxRiskScore: 69 })
    expect(riskRange('low', t)).toEqual({ maxRiskScore: 39 })
  })
})
