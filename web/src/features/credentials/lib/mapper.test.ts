import { describe, it, expect } from 'vitest'
import { mapCredentialToAsset } from './mapper'

describe('mapCredentialToAsset risk counts', () => {
  it.each(['critical', 'high', 'medium', 'low', 'info'])(
    'puts the one finding in the %s bucket',
    (severity) => {
      const row = mapCredentialToAsset({ id: 'c1', severity })
      expect(row.findingCount).toBe(1)
      expect(row.findingSeverityCounts).toEqual({ [severity]: 1 })
    }
  )

  it('leaves the breakdown empty when the severity is absent', () => {
    expect(mapCredentialToAsset({ id: 'c1' }).findingSeverityCounts).toEqual({})
  })
})
