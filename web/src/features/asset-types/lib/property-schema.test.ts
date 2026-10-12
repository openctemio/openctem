import { describe, expect, it } from 'vitest'

import {
  canonicalPropertyKey,
  groupProperties,
  propertyKeysOf,
  propertyLabel,
  propertyStrings,
} from './property-schema'
import { ASSET_PROPERTIES, ASSET_TYPE_PROPERTIES } from '../registry.generated'

describe('property schema', () => {
  it('folds every address synonym into ip_addresses', () => {
    expect(canonicalPropertyKey('resolved_ips')).toBe('ip_addresses')
    expect(canonicalPropertyKey('ip')).toBe('ip_addresses')
    expect(canonicalPropertyKey('title')).toBe('title')
    const got = propertyStrings(
      {
        ip: '203.0.113.1',
        ip_addresses: ['203.0.113.2'],
        resolved_ips: '203.0.113.3, 203.0.113.1; junk',
        ip_address: { address: '203.0.113.4', asn: 1 },
        addresses: ['2001:DB8::1'],
      },
      'ip_addresses'
    )
    // The key first, then each synonym in registry order, without duplicates.
    expect(got).toEqual(['203.0.113.2', '203.0.113.1', '203.0.113.4', '203.0.113.3', '2001:db8::1'])
  })

  it('labels a key in the viewer language, humanizing keys outside the schema', () => {
    expect(propertyLabel('ip_addresses')).toBe('IP addresses')
    expect(propertyLabel('ip_addresses', 'vi')).toBe('Địa chỉ IP')
    expect(propertyLabel('favorite_color')).toBe('Favorite color')
  })

  it('every attribute of every type has both labels', () => {
    for (const [type, keys] of Object.entries(ASSET_TYPE_PROPERTIES)) {
      for (const k of keys) {
        const def = ASSET_PROPERTIES[k]
        expect(def?.label, `${type}.${k}`).toBeTruthy()
        expect(def?.labelVi, `${type}.${k}`).toBeTruthy()
      }
    }
  })

  it('an alias sub-type adds the alias attributes to its core type', () => {
    const keys = propertyKeysOf('service', 'http')
    expect(keys).toContain('status_code') // http_service
    expect(keys).toContain('port') // service
    expect(keys).toContain('discovery_tool') // common
  })

  it('groups a domain: schema keys in order, synonyms folded once, the rest under Other', () => {
    const { known, other } = groupProperties(
      {
        ip: '198.51.100.20',
        ip_addresses: ['198.51.100.20'],
        registrar: 'Example Registrar',
        aliases: ['old.example.com'],
        x_vendor: 'kept',
        port: 443,
      },
      'domain'
    )
    expect(known.map((e) => e.key)).toEqual(['ip_addresses', 'registrar'])
    expect(known[0]).toEqual({ key: 'ip_addresses', value: ['198.51.100.20'], format: 'ip' })
    expect(other.map((e) => e.key)).toEqual(['port', 'x_vendor'])
  })

  it('shows addresses on a type whose schema has no ip_addresses, and keeps the technical block', () => {
    const { known, other } = groupProperties(
      { ip: '198.51.100.1', ip_address: { address: '198.51.100.1', asn: 64500 } },
      'certificate'
    )
    // ip_address is a common key (the technical block): a schema key of its own.
    expect(known.map((e) => e.key)).toEqual(['ip_address', 'ip_addresses'])
    expect(known[1]).toEqual({ key: 'ip_addresses', value: ['198.51.100.1'], format: 'ip' })
    expect(other).toEqual([])
  })
})
