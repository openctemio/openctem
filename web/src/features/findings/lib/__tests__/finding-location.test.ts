import { describe, expect, it } from 'vitest'

import { middleEllipsis } from '@/lib/middle-ellipsis'

import { findingLocation } from '../finding-location'

describe('findingLocation', () => {
  it('shows a URL on the asset host as its path, so two URLs of one app differ', () => {
    const a = findingLocation({
      asset: { name: 'https://shop.example.com' },
      file_path: 'https://shop.example.com/api/v2/customers/101/orders/export?format=csv',
    })
    const b = findingLocation({
      asset: { name: 'shop.example.com' },
      file_path: 'https://shop.example.com/api/v2/customers/101/payment-methods',
    })
    expect(a.asset).toBe('https://shop.example.com')
    expect(a.detail).toBe('/api/v2/customers/101/orders/export?format=csv')
    expect(b.detail).toBe('/api/v2/customers/101/payment-methods')
    expect(a.full).toBe('https://shop.example.com/api/v2/customers/101/orders/export?format=csv')
  })

  it('keeps a URL on another host whole', () => {
    const l = findingLocation({
      asset: { name: 'example.com' },
      file_path: 'https://cdn.other.net/x.js',
    })
    expect(l.detail).toBe('https://cdn.other.net/x.js')
    expect(l.full).toBe('example.com, https://cdn.other.net/x.js')
  })

  it('gives code findings branch, path and line next to the repository', () => {
    const l = findingLocation({
      asset: { name: 'github.com/acme/payments' },
      file_path: 'src/db/OrderRepository.java',
      start_line: 42,
      first_detected_branch: 'main',
    })
    expect(l).toEqual({
      asset: 'github.com/acme/payments',
      detail: 'main:src/db/OrderRepository.java:42',
      full: 'github.com/acme/payments, main:src/db/OrderRepository.java:42',
    })
  })

  it('shows the port of a network finding', () => {
    const l = findingLocation({
      asset: { name: 'vpn01.example.com' },
      network_port: 443,
      network_transport: 'tcp',
    })
    expect(l.detail).toBe(':443/tcp')
    expect(l.full).toBe('vpn01.example.com:443/tcp')
  })

  it('falls back to the affected targets of an asset-less finding', () => {
    const l = findingLocation({
      metadata: { affected_assets: ['10.0.0.1', '10.0.0.2', '10.0.0.3'] },
    })
    expect(l).toEqual({ asset: '', detail: '10.0.0.1 +2', full: '10.0.0.1 +2' })
  })

  it('drops a detail that only repeats the asset', () => {
    const l = findingLocation({ asset: { name: 'api.example.com' }, file_path: 'api.example.com' })
    expect(l.detail).toBe('')
    expect(l.full).toBe('api.example.com')
  })

  it('is empty when nothing is known', () => {
    expect(findingLocation({})).toEqual({ asset: '', detail: '', full: '' })
  })
})

describe('middleEllipsis', () => {
  it('leaves short values alone', () => {
    expect(middleEllipsis('/a/b', 20)).toBe('/a/b')
  })

  it('keeps the start and the (longer) end', () => {
    const out = middleEllipsis('/api/v2/customers/12345/orders/export?format=csv', 30)
    expect(Array.from(out)).toHaveLength(30)
    expect(out.startsWith('/api/v2')).toBe(true)
    expect(out.endsWith('/export?format=csv')).toBe(true)
    expect(out).toContain('…')
  })

  it('counts code points, never splitting a surrogate pair', () => {
    const out = middleEllipsis('😀'.repeat(30), 10)
    expect(Array.from(out)).toHaveLength(10)
    expect(out).not.toMatch(/[\uD800-\uDFFF](?![\uDC00-\uDFFF])/u)
  })
})
