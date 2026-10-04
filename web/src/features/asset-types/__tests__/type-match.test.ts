import { describe, expect, it } from 'vitest'

import {
  assetMatchesAnyTypeName,
  assetMatchesTypeName,
  canonicalAssetType,
} from '@/features/asset-types/type-match'
import {
  getValidRelationshipTypes,
  isValidRelationship,
} from '@/features/assets/types/relationship.types'
import { matchesScopeTarget } from '@/features/scope/lib/scope-matcher'
import type { ScopeTarget } from '@/features/scope/types'

// RFC-042 §6.3.8: only core types are stored, so a feature list that names
// `website` must match a stored application/website, never the string.
describe('assetMatchesTypeName', () => {
  it('resolves alias and virtual names to the stored pair', () => {
    expect(assetMatchesTypeName('website', { type: 'application', subType: 'website' })).toBe(true)
    expect(assetMatchesTypeName('website', { type: 'application', subType: 'api' })).toBe(false)
    expect(assetMatchesTypeName('k8s_cluster', { type: 'kubernetes', subType: 'cluster' })).toBe(
      true
    )
    expect(assetMatchesTypeName('firewall', { type: 'network', subType: 'firewall' })).toBe(true)
    expect(assetMatchesTypeName('s3_bucket', { type: 'storage', subType: 'bucket' })).toBe(true)
  })

  it('lets a core name cover every sub-type and an unknown kind match every name', () => {
    expect(assetMatchesTypeName('application', { type: 'application', subType: 'api' })).toBe(true)
    expect(assetMatchesTypeName('website', { type: 'application' })).toBe(true)
    expect(assetMatchesTypeName('website', { type: 'host' })).toBe(false)
  })

  it('reads a legacy row stored under an alias name as its pair', () => {
    expect(canonicalAssetType('website')).toEqual({ type: 'application', subType: 'website' })
    expect(assetMatchesTypeName('api', 'api')).toBe(true)
    expect(assetMatchesTypeName('website', 'api')).toBe(false)
  })

  it('handles an empty list', () => {
    expect(assetMatchesAnyTypeName(undefined, 'host')).toBe(false)
  })
})

// Probe for Q6: the dialog compared stored types with alias names, so an
// application, identity or kubernetes asset had no relationship to offer.
describe('relationship constraints by stored pair', () => {
  it('offers relationships for stored applications', () => {
    const app = { type: 'application', subType: 'website' }
    expect(getValidRelationshipTypes(app)).toContain('runs_on')
    expect(isValidRelationship('runs_on', app, { type: 'host' })).toBe(true)
    expect(isValidRelationship('runs_on', app, { type: 'kubernetes', subType: 'workload' })).toBe(
      true
    )
    expect(isValidRelationship('runs_on', { type: 'host' }, app)).toBe(false)
  })

  it('matches identity and kubernetes sub-types', () => {
    expect(
      isValidRelationship(
        'has_access_to',
        { type: 'identity', subType: 'iam_role' },
        { type: 'storage', subType: 'bucket' }
      )
    ).toBe(true)
    expect(
      isValidRelationship(
        'contains',
        { type: 'kubernetes', subType: 'cluster' },
        { type: 'kubernetes', subType: 'workload' }
      )
    ).toBe(true)
  })
})

describe('scope matcher by stored pair', () => {
  const target = (type: ScopeTarget['type'], pattern: string): ScopeTarget =>
    ({ id: 't', type, pattern, status: 'active' }) as ScopeTarget

  it('matches a stored web application against a website scope target', () => {
    const r = matchesScopeTarget(target('website', 'app.example.com'), {
      type: 'application',
      subType: 'website',
      name: 'app.example.com',
    })
    expect(r.matches).toBe(true)
  })

  it('does not match a mobile app against a website scope target', () => {
    const r = matchesScopeTarget(target('website', 'app.example.com'), {
      type: 'application',
      subType: 'mobile_app',
      name: 'app.example.com',
    })
    expect(r.matches).toBe(false)
  })
})
