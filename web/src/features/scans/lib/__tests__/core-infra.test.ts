import { describe, expect, it } from 'vitest'

import type { SensorCoreAddressesResponse } from '@/lib/api/sensor-types'

import { coreInfraHits } from '../core-infra'

const report: SensorCoreAddressesResponse = {
  items: [
    {
      sensor_id: 's1',
      sensor_name: 'scanner-hn',
      addresses: [
        { address: '10.0.0.53', role: 'resolver' },
        { address: '10.0.0.1', role: 'gateway' },
        { address: '10.0.0.10', role: 'platform' },
        { address: '2001:db8::53', role: 'resolver' },
      ],
    },
    {
      sensor_id: 's2',
      sensor_name: 'scanner-hcm',
      addresses: [
        { address: '10.0.0.53', role: 'resolver' },
        { address: 'not-an-ip', role: 'resolver' },
      ],
    },
  ],
}

describe('coreInfraHits', () => {
  it('names each covered address with every sensor and role', () => {
    const hits = coreInfraHits(['10.0.0.0/24', 'www.example.com'], report)
    expect(hits.map((h) => h.address)).toEqual(['10.0.0.53', '10.0.0.1', '10.0.0.10'])
    expect(hits[0].uses).toEqual([
      { sensorName: 'scanner-hn', role: 'resolver' },
      { sensorName: 'scanner-hcm', role: 'resolver' },
    ])
  })

  it('matches single addresses and IPv6 ranges', () => {
    expect(coreInfraHits(['10.0.0.1'], report).map((h) => h.address)).toEqual(['10.0.0.1'])
    expect(coreInfraHits(['2001:db8::/64'], report).map((h) => h.address)).toEqual(['2001:db8::53'])
  })

  it('never resolves names and ignores what is not covered', () => {
    expect(coreInfraHits(['dns.example.com', '192.0.2.0/24'], report)).toEqual([])
    expect(coreInfraHits([], report)).toEqual([])
    expect(coreInfraHits(['10.0.0.0/8'], undefined)).toEqual([])
  })
})
