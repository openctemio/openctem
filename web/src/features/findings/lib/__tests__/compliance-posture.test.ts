import { describe, expect, it } from 'vitest'
import { passRatePercent, passRateTone } from '../compliance-posture'
import {
  complianceControlAssetsUrl,
  complianceControlsUrl,
  findingComplianceHistoryUrl,
} from '../../api/compliance-checks-api'

describe('compliance posture helpers', () => {
  it('floors the pass rate so an almost-full rate never reads 100 %', () => {
    expect(passRatePercent(0.996)).toBe(99)
    expect(passRatePercent(1)).toBe(100)
    expect(passRatePercent(0)).toBe(0)
    expect(passRatePercent(null)).toBeNull()
    expect(passRatePercent(1.4)).toBe(100)
  })

  it('tones the rate', () => {
    expect(passRateTone(0.5)).toBe('destructive')
    expect(passRateTone(0.8)).toBe('warning')
    expect(passRateTone(0.95)).toBe('success')
    expect(passRateTone(null)).toBe('default')
  })

  it('builds the read URLs with every part encoded', () => {
    expect(
      complianceControlsUrl('cis-x', { failedOnly: true, q: ' 1.1 ', page: 2, perPage: 50 })
    ).toBe(
      '/api/v1/findings/compliance/benchmarks/cis-x/controls?result=fail%2Cmanual&q=1.1&page=2&per_page=50'
    )
    expect(complianceControlsUrl('cis-x')).toBe(
      '/api/v1/findings/compliance/benchmarks/cis-x/controls'
    )
    expect(complianceControlAssetsUrl('cis-x', 'a/b c')).toBe(
      '/api/v1/findings/compliance/benchmarks/cis-x/assets?control=a%2Fb%20c&per_page=100'
    )
    expect(findingComplianceHistoryUrl('f/1')).toBe('/api/v1/findings/f%2F1/compliance-history')
  })
})
