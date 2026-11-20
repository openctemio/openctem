import { describe, expect, it } from 'vitest'
import { currentAddressGroups, type NameAddress } from '../use-name-addresses'

const a = (address: string, current: boolean, provider?: string): NameAddress => ({
  address,
  provider,
  current,
  first_seen: '2026-11-01T00:00:00Z',
  last_seen: '2026-11-18T00:00:00Z',
  sources: [],
})

describe('currentAddressGroups', () => {
  it('groups current addresses by provider, providers first, past ones left out', () => {
    const groups = currentAddressGroups([
      a('198.51.100.7', true),
      a('13.107.128.10', true, 'Microsoft 365'),
      a('3.11.53.20', false, 'Amazon CloudFront'),
      a('13.107.128.11', true, 'Microsoft 365'),
      a('3.11.53.21', true, 'Amazon CloudFront'),
    ])
    expect(groups).toEqual([
      { provider: 'Amazon CloudFront', addresses: ['3.11.53.21'] },
      { provider: 'Microsoft 365', addresses: ['13.107.128.10', '13.107.128.11'] },
      { provider: '', addresses: ['198.51.100.7'] },
    ])
  })
})
