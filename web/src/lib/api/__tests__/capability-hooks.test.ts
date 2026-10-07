import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import { fetchAllCapabilities } from '@/lib/api/capability-hooks'
import { capabilityEndpoints } from '@/lib/api/endpoints'

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function page(n: number, totalPages: number, names: string[]) {
  return {
    items: names.map((name) => ({ id: `id-${name}`, name, source: 'platform' })),
    total: names.length,
    page: n,
    per_page: 100,
    total_pages: totalPages,
    meta: { omitted_includes: [] },
  }
}

describe('capabilities: one collection', () => {
  const fetchMock = vi.fn()
  beforeEach(() => vi.stubGlobal('fetch', fetchMock))
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('reads every page of /capabilities, with include=usage when asked', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, page(1, 2, ['sast', 'sca'])))
      .mockResolvedValueOnce(jsonResponse(200, page(2, 2, ['dast'])))

    const all = await fetchAllCapabilities(true)

    expect(all.map((c) => c.name)).toEqual(['sast', 'sca', 'dast'])
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const urls = fetchMock.mock.calls.map((c) => String(c[0]))
    for (const u of urls) {
      expect(u).toContain('/api/v1/capabilities?')
      expect(u).toContain('include=usage')
      expect(u).toContain('per_page=100')
      expect(u).not.toContain('/all')
    }
    expect(urls[1]).toContain('page=2')
  })

  it('writes go to /capabilities; the custom-capabilities paths are gone', () => {
    expect(capabilityEndpoints.create()).toBe('/api/v1/capabilities')
    expect(capabilityEndpoints.update('c1')).toBe('/api/v1/capabilities/c1')
    expect(capabilityEndpoints.delete('c1', true)).toBe('/api/v1/capabilities/c1?force=true')
    expect(capabilityEndpoints.get('c1', 'usage')).toBe('/api/v1/capabilities/c1?include=usage')
    expect(Object.keys(capabilityEndpoints)).not.toContain('usageStatsBatch')
  })
})
