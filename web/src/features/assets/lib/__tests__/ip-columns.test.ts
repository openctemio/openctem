import { describe, expect, it } from 'vitest'
import { formatPort, networkFilter, shownWithMore } from '../ip-columns'

describe('the IP addresses tab columns', () => {
  it('writes a port as 443/tcp https', () => {
    expect(formatPort({ port: 443, transport: 'tcp', service: 'https' })).toBe('443/tcp https')
    expect(formatPort({ port: 53, transport: 'udp' })).toBe('53/udp')
    expect(formatPort({ port: 8080 })).toBe('8080')
  })

  it('shows the first values and how many more there are', () => {
    expect(shownWithMore(['a', 'b', 'c'], 7, 3)).toEqual({ shown: ['a', 'b', 'c'], more: 4 })
    expect(shownWithMore(['a'], 1, 3)).toEqual({ shown: ['a'], more: 0 })
    // A total below what is listed never goes negative.
    expect(shownWithMore(['a', 'b'], 0, 3)).toEqual({ shown: ['a', 'b'], more: 0 })
  })

  it('filters by a network only when it is a CIDR', () => {
    expect(networkFilter('198.51.100.0/24')).toBe('198.51.100.0/24')
    expect(networkFilter('2001:db8::/64')).toBe('2001:db8::/64')
    expect(networkFilter('<script>')).toBeUndefined()
    expect(networkFilter(undefined)).toBeUndefined()
  })
})
