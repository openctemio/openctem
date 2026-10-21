import { describe, it, expect } from 'vitest'
import { loweredRiskFields } from '../risk-impact'

describe('loweredRiskFields', () => {
  const asset = { exposure: 'public', criticality: 'high' }

  it('is empty when nothing changes or risk goes up', () => {
    expect(loweredRiskFields(asset, { exposure: 'public', criticality: 'high' })).toEqual([])
    expect(loweredRiskFields(asset, { exposure: 'public', criticality: 'critical' })).toEqual([])
    expect(
      loweredRiskFields({ exposure: 'isolated', criticality: 'low' }, { exposure: 'public' })
    ).toEqual([])
  })

  it('reports a lower exposure', () => {
    expect(loweredRiskFields(asset, { exposure: 'isolated' })).toEqual(['exposure'])
    expect(loweredRiskFields(asset, { exposure: 'private' })).toEqual(['exposure'])
    expect(loweredRiskFields(asset, { exposure: 'restricted' })).toEqual(['exposure'])
  })

  it('reports a lower criticality, including not rated', () => {
    expect(loweredRiskFields(asset, { criticality: 'low' })).toEqual(['criticality'])
    expect(loweredRiskFields(asset, { criticality: 'none' })).toEqual(['criticality'])
  })

  it('treats unknown like restricted', () => {
    expect(loweredRiskFields({ exposure: 'restricted' }, { exposure: 'unknown' })).toEqual([])
    expect(loweredRiskFields({ exposure: 'unknown' }, { exposure: 'private' })).toEqual([
      'exposure',
    ])
  })

  it('reports both when both are lowered', () => {
    expect(loweredRiskFields(asset, { exposure: 'isolated', criticality: 'low' })).toEqual([
      'exposure',
      'criticality',
    ])
  })
})
