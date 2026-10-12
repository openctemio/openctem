/**
 * The scan wizard's coverage expansion asks the inventory once for every
 * typed domain (GET /assets?under=a,b), not one search per domain
 * (research/81).
 */
import * as React from 'react'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))

import { coverageURL, useCoverageExpansion } from '../use-coverage-expansion'

function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

describe('useCoverageExpansion', () => {
  beforeEach(() => get.mockReset())

  it('asks once for all the typed domains', async () => {
    get.mockResolvedValue({
      data: [
        { name: 'api.example.com', properties: { resolved_ips: ['203.0.113.1'] } },
        { name: 'www.example.org', properties: { resolved_ips: ['203.0.113.2'] } },
      ],
      total: 2,
    })
    const { result } = renderHook(
      () => useCoverageExpansion(['example.com', 'example.org'], 'subdomains_ips'),
      { wrapper }
    )
    await waitFor(() => expect(result.current.added).toEqual(['203.0.113.1', '203.0.113.2']))
    expect(get).toHaveBeenCalledTimes(1)
    expect(get).toHaveBeenCalledWith(coverageURL(['example.com', 'example.org'], 1))
    expect(String(get.mock.calls[0][0])).toContain('under=example.com%2Cexample.org')
  })

  it('reads a second page only when the inventory holds more names', async () => {
    const full = Array.from({ length: 100 }, (_, i) => ({ name: `h${i}.example.com` }))
    get
      .mockResolvedValueOnce({ data: full, total: 130 })
      .mockResolvedValueOnce({ data: full.slice(0, 30), total: 130 })
    renderHook(() => useCoverageExpansion(['example.com'], 'subdomains_ips'), { wrapper })
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(String(get.mock.calls[1][0])).toContain('page=2')
  })

  it('sends nothing for host-only coverage', () => {
    renderHook(() => useCoverageExpansion(['example.com'], 'host'), { wrapper })
    expect(get).not.toHaveBeenCalled()
  })

  it('lists nothing for subdomains: the run resolves *.domain itself (RFC-068)', () => {
    const { result } = renderHook(() => useCoverageExpansion(['example.com'], 'subdomains'), {
      wrapper,
    })
    expect(get).not.toHaveBeenCalled()
    expect(result.current.added).toEqual([])
  })
})
