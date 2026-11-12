/**
 * What the inventory sends to GET /assets: the list query contract's own
 * parameter names. The old names still work on the server but are deprecated,
 * and an unknown parameter is refused, so nothing else may be sent.
 */
import { describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))

import { buildAssetQueryParams } from '../use-assets'

/** The registry's parameter names of GET /assets that the inventory writes. */
const KNOWN = new Set([
  'page',
  'per_page',
  'sort',
  'with_triage',
  'properties',
  'name',
  'q',
  'type',
  'lens',
  'sub_type',
  'criticality',
  'status',
  'scope',
  'exposure',
  'tag',
  'tag_all',
  'tag_not',
  'risk_score_gte',
  'risk_score_lte',
  'has_findings',
  'crown_jewel',
  'primary',
  'program_assets',
  'freshness',
  'resolution',
  'coverage',
  'coverage_cause',
  'technology',
  'technology_category',
  'technology_version',
  'business_unit',
  'has_owner',
  'data_classification',
  'control_plane',
  'internet_facing',
  'environment',
  'provider',
  'last_seen_lte',
  'last_seen_gte',
  'expires_gt',
  'expires_lt',
  'attribution',
  'scope_status',
  'monitoring_state',
  'liveness',
  'discovered_by',
  'created_at_gte',
  'created_at_lte',
  'fq',
  'ip',
  'network',
  'port_gte',
  'sub_type_not',
])

describe('the inventory list params', () => {
  it('sends only the list contract names, never a deprecated one', () => {
    const p = buildAssetQueryParams({
      page: 2,
      pageSize: 50,
      name: 'x',
      types: ['host'],
      lenses: ['data'],
      subType: 'http',
      criticalities: ['high'],
      statuses: ['active'],
      scopes: ['external'],
      exposures: ['public'],
      tags: ['t'],
      excludeTags: ['u'],
      search: 'web',
      minRiskScore: 70,
      maxRiskScore: 90,
      hasFindings: true,
      isCrownJewel: true,
      isPrimary: true,
      programAssets: 'only',
      freshness: 'stale',
      resolution: 'resolving',
      coverage: 'covered',
      technologies: ['nginx'],
      technologyCategories: ['web_server'],
      technologyVersion: '1.2',
      businessUnitIds: ['b1'],
      hasOwner: false,
      dataClassifications: ['secret'],
      isControlPlane: true,
      isInternetFacing: true,
      environments: ['production'],
      providers: ['aws'],
      lastSeenBefore: 'a',
      lastSeenAfter: 'b',
      expiresAfter: 'c',
      expiresBefore: 'd',
      attribution: ['approved'],
      scopeStatus: ['in_scope'],
      monitoringState: ['monitored'],
      liveness: ['alive'],
      discoveredBy: ['tenant_scanned'],
      firstSeenAfter: 'e',
      firstSeenBefore: 'f',
      withTriage: true,
      sort: '-risk_score',
      extra: { network: '198.51.100.0/24', port_gte: '1', sub_type_not: 'discovered_url' },
      propertiesFilter: { os: ['linux'] },
    })
    const unknown = Object.keys(p).filter((k) => !KNOWN.has(k))
    expect(unknown).toEqual([])
    expect(p).toMatchObject({
      q: 'web',
      type: 'host',
      criticality: 'high',
      risk_score_gte: '70',
      crown_jewel: 'true',
      business_unit: 'b1',
      last_seen_lte: 'a',
      last_seen_gte: 'b',
      created_at_gte: 'e',
      network: '198.51.100.0/24',
    })
  })

  it('an extra never overrides what the page itself sends', () => {
    expect(buildAssetQueryParams({ types: ['host'], extra: { type: 'domain' } }).type).toBe('host')
  })

  it('a filter given as text travels as fq, never as list params', () => {
    const p = buildAssetQueryParams({ advanced: 'port=22 OR port=23', types: ['ip_address'] })
    expect(p.fq).toBe('port=22 OR port=23')
    expect(p.type).toBe('ip_address')
  })
})
