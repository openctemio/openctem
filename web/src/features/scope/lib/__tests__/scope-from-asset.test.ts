import { describe, expect, it } from 'vitest'
import {
  hostOf,
  scopeDraftForAsset,
  scopeItemForAsset,
  scopeItemsForAssets,
} from '../scope-from-asset'

describe('scopeItemForAsset', () => {
  it('a name or a public address becomes an exact entry, never a wildcard', () => {
    expect(scopeItemForAsset('API.Example.com.')).toEqual({
      item: { target_type: 'domain', pattern: 'api.example.com' },
    })
    expect(scopeItemForAsset('203.0.113.9')).toEqual({
      item: { target_type: 'ip_address', pattern: '203.0.113.9' },
    })
    expect(scopeItemForAsset('198.51.100.0/24')).toEqual({
      item: { target_type: 'ip_range', pattern: '198.51.100.0/24' },
    })
    expect(scopeItemForAsset('*.example.com').skip).toBe('unrecognized')
  })

  it('a URL or a service is covered by its host', () => {
    expect(scopeItemForAsset('https://shop.example.com:8443/login').item?.pattern).toBe(
      'shop.example.com'
    )
    expect(scopeItemForAsset('mail.example.com:25:tcp').item?.pattern).toBe('mail.example.com')
    expect(scopeItemForAsset('203.0.113.9:443/tcp').item).toEqual({
      target_type: 'ip_address',
      pattern: '203.0.113.9',
    })
    expect(hostOf('[2001:db8::1]:443')).toBe('2001:db8::1')
  })

  it('private and internal targets are left to scan zones; repositories need no entry', () => {
    for (const n of [
      '10.0.0.5',
      '192.168.1.0/24',
      'db.internal',
      'http://172.20.1.1/',
      'printer.local',
    ])
      expect(scopeItemForAsset(n).skip).toBe('internal')
    expect(scopeItemForAsset('github.com/acme/web').skip).toBe('no_entry_needed')
    expect(scopeItemForAsset('AWS:123456789012').skip).toBe('no_entry_needed')
    expect(scopeItemForAsset('not a host').skip).toBe('unrecognized')
  })

  it('a selection is de-duplicated and the skips are counted by reason', () => {
    const { items, skipped } = scopeItemsForAssets([
      'a.example.com',
      'https://a.example.com/x',
      'a.example.com:443:tcp',
      '10.1.1.1',
      'github.com/acme/web',
    ])
    expect(items).toEqual([{ target_type: 'domain', pattern: 'a.example.com' }])
    expect(skipped).toEqual({ internal: 1, no_entry_needed: 1 })
  })
})

describe('scopeDraftForAsset', () => {
  it('a service asset starts the dialog with its host address, not host:port:proto', () => {
    expect(scopeDraftForAsset('162.159.141.75:8443:tcp')).toEqual({
      pattern: '162.159.141.75',
      target_type: 'ip_address',
    })
    expect(scopeDraftForAsset('https://app.example.com/login')).toEqual({
      pattern: 'app.example.com',
      target_type: 'domain',
    })
  })

  it('keeps the name and the given kind when no entry can be derived', () => {
    expect(scopeDraftForAsset('github.com/acme/repo', 'repository')).toEqual({
      pattern: 'github.com/acme/repo',
      target_type: 'repository',
    })
  })
})
