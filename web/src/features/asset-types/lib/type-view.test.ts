import { describe, expect, it } from 'vitest'
import type { AssetTypeRegistry } from './asset-registry'
import { MAX_TYPE_FACETS, typeViewOf } from './type-view'

const registry = {
  types: [
    {
      type: 'host',
      label: 'Host',
      plural: 'Hosts',
      attributes: [
        { name: 'os_family', type: 'enum', values: ['linux', 'windows'], facet: true },
        { name: 'os_name', type: 'string', facet: true },
        { name: 'ip_addresses', type: 'list' },
        { name: 'is_virtual', type: 'bool', facet: true },
        { name: 'cpu_count', type: 'int' },
        { name: 'not_a_schema_key', type: 'string', facet: true },
      ],
      columns: ['name', 'os_name', 'ip_addresses', 'findings.open', 'last_seen', 'owner'],
      scannable_by: ['host', 'ip'],
    },
    {
      type: 'identity',
      label: 'Identity',
      plural: 'Identities',
      attributes: [{ name: 'provider', type: 'string', facet: true }],
      columns: ['name', 'provider'],
      scannable_by: [],
    },
    {
      type: 'iam_user',
      label: 'IAM User',
      plural: 'IAM Users',
      alias_of: { type: 'identity', sub_type: 'iam_user' },
      attributes: [{ name: 'has_mfa', type: 'bool', facet: true }],
      columns: ['name', 'provider', 'has_mfa'],
    },
  ],
} as unknown as AssetTypeRegistry

describe('typeViewOf', () => {
  it('is null for a mixed list or before the registry loads', () => {
    expect(typeViewOf(registry, undefined)).toBeNull()
    expect(typeViewOf(registry, ['host', 'identity'])).toBeNull()
    expect(typeViewOf(undefined, ['host'])).toBeNull()
    expect(typeViewOf(registry, ['nope'])).toBeNull()
  })

  it('takes columns, facets and scannability from the registry, schema keys only', () => {
    const v = typeViewOf(registry, ['host'])!
    expect(v.plural).toBe('Hosts')
    expect(v.columns.map((c) => c.key)).toEqual(['os_name', 'ip_addresses'])
    expect(v.facets.map((f) => f.key)).toEqual(['os_family', 'os_name', 'is_virtual'])
    expect(v.facets[0].values).toEqual(['linux', 'windows'])
    expect(v.attributes.some((a) => (a.key as string) === 'not_a_schema_key')).toBe(false)
    expect(v.scannable).toBe(true)
  })

  it("an alias sub-type gets its own label and columns, then the core type's attributes", () => {
    const v = typeViewOf(registry, ['identity'], 'iam_user')!
    expect(v.label).toBe('IAM User')
    expect(v.subType).toBe('iam_user')
    expect(v.attributes.map((a) => a.key)).toEqual(['has_mfa', 'provider'])
    expect(v.columns.map((c) => c.key)).toEqual(['provider', 'has_mfa'])
    expect(v.scannable).toBe(false)
  })

  it('caps the facets at the stats count_by limit', () => {
    const many = {
      types: [
        {
          type: 'host',
          attributes: Array.from({ length: 14 }, (_, i) => ({
            name: ['os_name', 'os_family', 'architecture', 'hypervisor', 'is_virtual'][i % 5],
            type: 'string',
            facet: true,
          })),
        },
      ],
    } as unknown as AssetTypeRegistry
    expect(typeViewOf(many, ['host'])!.facets.length).toBeLessThanOrEqual(MAX_TYPE_FACETS)
  })
})
